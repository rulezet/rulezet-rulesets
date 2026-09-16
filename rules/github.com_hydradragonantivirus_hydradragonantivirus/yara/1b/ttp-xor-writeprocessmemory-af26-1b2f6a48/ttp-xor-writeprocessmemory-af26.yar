rule TTP_XOR_WriteProcessMemory_af26 {
  strings:
    $key_af26 = { f8 54 [2] ca 76 [2] cc 43 [2] e2 43 [2] dd 5f }

  condition:
    any of them
}