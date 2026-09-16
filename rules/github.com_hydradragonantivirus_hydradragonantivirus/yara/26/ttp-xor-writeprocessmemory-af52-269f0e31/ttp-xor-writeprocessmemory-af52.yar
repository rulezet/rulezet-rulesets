rule TTP_XOR_WriteProcessMemory_af52 {
  strings:
    $key_af52 = { f8 20 [2] ca 02 [2] cc 37 [2] e2 37 [2] dd 2b }

  condition:
    any of them
}