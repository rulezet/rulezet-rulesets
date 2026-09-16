rule PEiD_01926_RCryptor_v1_5_____Vaska_ {
  meta:
    description = "[RCryptor v1.5 --> Vaska]"
    ep_only     = "true"

  strings:
    $a = { 83 2C 24 4F 68 ?? ?? ?? ?? FF 54 24 04 83 44 24 04 4F }

  condition:
    $a
}