rule TTP_XOR_WriteProcessMemory_8197 {
  strings:
    $key_8197 = { d6 e5 [2] e4 c7 [2] e2 f2 [2] cc f2 [2] f3 ee }

  condition:
    any of them
}