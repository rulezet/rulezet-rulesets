rule TTP_XOR_WriteProcessMemory_0b36 {
  strings:
    $key_0b36 = { 5c 44 [2] 6e 66 [2] 68 53 [2] 46 53 [2] 79 4f }

  condition:
    any of them
}