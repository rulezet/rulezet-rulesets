rule TTP_XOR_WriteProcessMemory_af5d {
  strings:
    $key_af5d = { f8 2f [2] ca 0d [2] cc 38 [2] e2 38 [2] dd 24 }

  condition:
    any of them
}