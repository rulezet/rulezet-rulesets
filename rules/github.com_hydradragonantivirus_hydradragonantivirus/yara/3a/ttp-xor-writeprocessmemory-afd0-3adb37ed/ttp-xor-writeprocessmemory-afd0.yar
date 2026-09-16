rule TTP_XOR_WriteProcessMemory_afd0 {
  strings:
    $key_afd0 = { f8 a2 [2] ca 80 [2] cc b5 [2] e2 b5 [2] dd a9 }

  condition:
    any of them
}