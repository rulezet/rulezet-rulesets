rule TTP_XOR_WriteProcessMemory_0b72 {
  strings:
    $key_0b72 = { 5c 00 [2] 6e 22 [2] 68 17 [2] 46 17 [2] 79 0b }

  condition:
    any of them
}