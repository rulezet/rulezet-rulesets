rule TTP_XOR_WriteProcessMemory_8695 {
  strings:
    $key_8695 = { d1 e7 [2] e3 c5 [2] e5 f0 [2] cb f0 [2] f4 ec }

  condition:
    any of them
}