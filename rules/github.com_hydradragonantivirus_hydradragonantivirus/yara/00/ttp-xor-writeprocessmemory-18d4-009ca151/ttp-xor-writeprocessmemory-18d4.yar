rule TTP_XOR_WriteProcessMemory_18d4 {
  strings:
    $key_18d4 = { 4f a6 [2] 7d 84 [2] 7b b1 [2] 55 b1 [2] 6a ad }

  condition:
    any of them
}