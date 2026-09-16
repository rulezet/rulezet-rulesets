rule TTP_XOR_WriteProcessMemory_8382 {
  strings:
    $key_8382 = { d4 f0 [2] e6 d2 [2] e0 e7 [2] ce e7 [2] f1 fb }

  condition:
    any of them
}