rule TTP_XOR_WriteProcessMemory_0a8f {
  strings:
    $key_0a8f = { 5d fd [2] 6f df [2] 69 ea [2] 47 ea [2] 78 f6 }

  condition:
    any of them
}