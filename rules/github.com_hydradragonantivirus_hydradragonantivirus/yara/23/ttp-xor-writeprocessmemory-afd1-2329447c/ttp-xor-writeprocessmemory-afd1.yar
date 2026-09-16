rule TTP_XOR_WriteProcessMemory_afd1 {
  strings:
    $key_afd1 = { f8 a3 [2] ca 81 [2] cc b4 [2] e2 b4 [2] dd a8 }

  condition:
    any of them
}