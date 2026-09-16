rule TTP_XOR_WriteProcessMemory_8795 {
  strings:
    $key_8795 = { d0 e7 [2] e2 c5 [2] e4 f0 [2] ca f0 [2] f5 ec }

  condition:
    any of them
}