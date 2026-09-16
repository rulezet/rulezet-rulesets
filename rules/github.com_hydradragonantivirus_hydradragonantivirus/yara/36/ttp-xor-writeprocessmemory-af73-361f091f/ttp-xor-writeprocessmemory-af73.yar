rule TTP_XOR_WriteProcessMemory_af73 {
  strings:
    $key_af73 = { f8 01 [2] ca 23 [2] cc 16 [2] e2 16 [2] dd 0a }

  condition:
    any of them
}