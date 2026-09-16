rule TTP_XOR_WriteProcessMemory_2a84 {
  strings:
    $key_2a84 = { 7d f6 [2] 4f d4 [2] 49 e1 [2] 67 e1 [2] 58 fd }

  condition:
    any of them
}