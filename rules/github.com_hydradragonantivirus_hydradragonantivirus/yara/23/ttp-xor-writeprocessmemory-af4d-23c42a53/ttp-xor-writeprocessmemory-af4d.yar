rule TTP_XOR_WriteProcessMemory_af4d {
  strings:
    $key_af4d = { f8 3f [2] ca 1d [2] cc 28 [2] e2 28 [2] dd 34 }

  condition:
    any of them
}