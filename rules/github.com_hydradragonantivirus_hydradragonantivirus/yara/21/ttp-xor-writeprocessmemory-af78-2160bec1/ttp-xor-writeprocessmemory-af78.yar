rule TTP_XOR_WriteProcessMemory_af78 {
  strings:
    $key_af78 = { f8 0a [2] ca 28 [2] cc 1d [2] e2 1d [2] dd 01 }

  condition:
    any of them
}