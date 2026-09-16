rule TTP_XOR_WriteProcessMemory_afc0 {
  strings:
    $key_afc0 = { f8 b2 [2] ca 90 [2] cc a5 [2] e2 a5 [2] dd b9 }

  condition:
    any of them
}