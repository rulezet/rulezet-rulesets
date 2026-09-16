rule TTP_XOR_WriteProcessMemory_9395 {
  strings:
    $key_9395 = { c4 e7 [2] f6 c5 [2] f0 f0 [2] de f0 [2] e1 ec }

  condition:
    any of them
}