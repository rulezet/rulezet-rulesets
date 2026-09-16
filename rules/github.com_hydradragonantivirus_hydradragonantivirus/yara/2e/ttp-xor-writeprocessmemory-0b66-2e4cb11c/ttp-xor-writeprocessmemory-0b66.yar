rule TTP_XOR_WriteProcessMemory_0b66 {
  strings:
    $key_0b66 = { 5c 14 [2] 6e 36 [2] 68 03 [2] 46 03 [2] 79 1f }

  condition:
    any of them
}