rule TTP_XOR_WriteProcessMemory_8782 {
  strings:
    $key_8782 = { d0 f0 [2] e2 d2 [2] e4 e7 [2] ca e7 [2] f5 fb }

  condition:
    any of them
}