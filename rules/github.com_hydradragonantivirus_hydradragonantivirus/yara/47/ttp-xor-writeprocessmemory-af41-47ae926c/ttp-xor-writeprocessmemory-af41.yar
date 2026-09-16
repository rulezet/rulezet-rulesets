rule TTP_XOR_WriteProcessMemory_af41 {
  strings:
    $key_af41 = { f8 33 [2] ca 11 [2] cc 24 [2] e2 24 [2] dd 38 }

  condition:
    any of them
}