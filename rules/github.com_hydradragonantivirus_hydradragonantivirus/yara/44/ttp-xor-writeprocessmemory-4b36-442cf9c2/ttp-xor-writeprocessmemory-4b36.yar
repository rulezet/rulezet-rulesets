rule TTP_XOR_WriteProcessMemory_4b36 {
  strings:
    $key_4b36 = { 1c 44 [2] 2e 66 [2] 28 53 [2] 06 53 [2] 39 4f }

  condition:
    any of them
}