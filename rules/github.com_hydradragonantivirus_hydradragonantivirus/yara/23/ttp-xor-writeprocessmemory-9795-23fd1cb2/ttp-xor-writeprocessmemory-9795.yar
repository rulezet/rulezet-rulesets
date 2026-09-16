rule TTP_XOR_WriteProcessMemory_9795 {
  strings:
    $key_9795 = { c0 e7 [2] f2 c5 [2] f4 f0 [2] da f0 [2] e5 ec }

  condition:
    any of them
}