rule TTP_XOR_WriteProcessMemory_2984 {
  strings:
    $key_2984 = { 7e f6 [2] 4c d4 [2] 4a e1 [2] 64 e1 [2] 5b fd }

  condition:
    any of them
}