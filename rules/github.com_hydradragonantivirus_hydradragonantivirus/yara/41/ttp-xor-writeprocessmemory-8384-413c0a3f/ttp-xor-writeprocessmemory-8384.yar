rule TTP_XOR_WriteProcessMemory_8384 {
  strings:
    $key_8384 = { d4 f6 [2] e6 d4 [2] e0 e1 [2] ce e1 [2] f1 fd }

  condition:
    any of them
}