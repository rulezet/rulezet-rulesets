rule TTP_XOR_WriteProcessMemory_af61 {
  strings:
    $key_af61 = { f8 13 [2] ca 31 [2] cc 04 [2] e2 04 [2] dd 18 }

  condition:
    any of them
}