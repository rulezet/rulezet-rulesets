rule TTP_XOR_WriteProcessMemory_3484 {
  strings:
    $key_3484 = { 63 f6 [2] 51 d4 [2] 57 e1 [2] 79 e1 [2] 46 fd }

  condition:
    any of them
}