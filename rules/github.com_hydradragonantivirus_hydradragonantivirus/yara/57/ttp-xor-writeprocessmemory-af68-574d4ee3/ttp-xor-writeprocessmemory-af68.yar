rule TTP_XOR_WriteProcessMemory_af68 {
  strings:
    $key_af68 = { f8 1a [2] ca 38 [2] cc 0d [2] e2 0d [2] dd 11 }

  condition:
    any of them
}