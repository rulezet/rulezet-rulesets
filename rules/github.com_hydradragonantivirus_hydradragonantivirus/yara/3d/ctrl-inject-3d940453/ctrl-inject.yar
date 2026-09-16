rule CTRL_Inject {
  meta:
    author      = "McAfee ATR - Thomas Roccia - @fr0gger_ "
    description = "Detect Control Inject"
    reference   = "https://blog.ensilo.com/ctrl-inject"
    mitre_id    = "T1055"

  strings:
    $func1 = "OpenProcess" nocase
    $func2 = "VirtualAllocEx" nocase
    $func3 = "WriteProcessMemory" nocase
    $func4 = "EncodePointer" nocase
    $func5 = "EncodeRemotePointer" nocase
    $func6 = "SetProcessValidCallTargets" nocase

  condition:
    uint16(0) == 0x5A4D and ($func1 and $func2 and ($func4 or $func5) and $func6 or (all of them))

}