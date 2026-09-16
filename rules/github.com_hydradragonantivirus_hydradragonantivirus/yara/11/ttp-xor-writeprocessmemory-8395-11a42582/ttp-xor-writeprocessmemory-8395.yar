rule TTP_XOR_WriteProcessMemory_8395 {
  strings:
    $key_8395 = { d4 e7 [2] e6 c5 [2] e0 f0 [2] ce f0 [2] f1 ec }

  condition:
    any of them
}