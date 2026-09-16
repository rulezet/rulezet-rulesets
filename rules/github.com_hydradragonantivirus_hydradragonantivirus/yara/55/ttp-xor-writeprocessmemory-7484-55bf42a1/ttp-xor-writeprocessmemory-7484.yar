rule TTP_XOR_WriteProcessMemory_7484 {
  strings:
    $key_7484 = { 23 f6 [2] 11 d4 [2] 17 e1 [2] 39 e1 [2] 06 fd }

  condition:
    any of them
}