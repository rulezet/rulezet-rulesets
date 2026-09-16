rule TTP_XOR_WriteProcessMemory_1a8f {
  strings:
    $key_1a8f = { 4d fd [2] 7f df [2] 79 ea [2] 57 ea [2] 68 f6 }

  condition:
    any of them
}