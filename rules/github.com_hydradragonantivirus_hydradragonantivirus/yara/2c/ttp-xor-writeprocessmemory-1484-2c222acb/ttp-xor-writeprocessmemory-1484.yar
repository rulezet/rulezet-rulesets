rule TTP_XOR_WriteProcessMemory_1484 {
  strings:
    $key_1484 = { 43 f6 [2] 71 d4 [2] 77 e1 [2] 59 e1 [2] 66 fd }

  condition:
    any of them
}