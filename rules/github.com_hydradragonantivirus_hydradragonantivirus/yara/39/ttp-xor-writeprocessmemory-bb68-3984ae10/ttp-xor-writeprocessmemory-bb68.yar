rule TTP_XOR_WriteProcessMemory_bb68 {
  strings:
    $key_bb68 = { ec 1a [2] de 38 [2] d8 0d [2] f6 0d [2] c9 11 }

  condition:
    any of them
}