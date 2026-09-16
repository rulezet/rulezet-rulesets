rule TTP_XOR_WriteProcessMemory_8794 {
  strings:
    $key_8794 = { d0 e6 [2] e2 c4 [2] e4 f1 [2] ca f1 [2] f5 ed }

  condition:
    any of them
}