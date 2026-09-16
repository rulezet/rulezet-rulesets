rule TTP_XOR_WriteProcessMemory_8796 {
  strings:
    $key_8796 = { d0 e4 [2] e2 c6 [2] e4 f3 [2] ca f3 [2] f5 ef }

  condition:
    any of them
}