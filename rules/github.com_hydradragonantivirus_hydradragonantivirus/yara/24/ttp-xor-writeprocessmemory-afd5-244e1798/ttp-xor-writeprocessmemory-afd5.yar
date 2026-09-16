rule TTP_XOR_WriteProcessMemory_afd5 {
  strings:
    $key_afd5 = { f8 a7 [2] ca 85 [2] cc b0 [2] e2 b0 [2] dd ac }

  condition:
    any of them
}