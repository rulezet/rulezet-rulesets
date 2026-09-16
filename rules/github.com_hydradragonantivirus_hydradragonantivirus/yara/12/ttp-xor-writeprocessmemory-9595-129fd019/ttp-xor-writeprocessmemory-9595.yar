rule TTP_XOR_WriteProcessMemory_9595 {
  strings:
    $key_9595 = { c2 e7 [2] f0 c5 [2] f6 f0 [2] d8 f0 [2] e7 ec }

  condition:
    any of them
}