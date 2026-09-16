rule TTP_XOR_WriteProcessMemory_af50 {
  strings:
    $key_af50 = { f8 22 [2] ca 00 [2] cc 35 [2] e2 35 [2] dd 29 }

  condition:
    any of them
}