rule TTP_XOR_WriteProcessMemory_afd6 {
  strings:
    $key_afd6 = { f8 a4 [2] ca 86 [2] cc b3 [2] e2 b3 [2] dd af }

  condition:
    any of them
}