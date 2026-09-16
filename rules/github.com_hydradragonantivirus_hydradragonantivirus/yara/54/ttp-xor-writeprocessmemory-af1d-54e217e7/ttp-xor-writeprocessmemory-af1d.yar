rule TTP_XOR_WriteProcessMemory_af1d {
  strings:
    $key_af1d = { f8 6f [2] ca 4d [2] cc 78 [2] e2 78 [2] dd 64 }

  condition:
    any of them
}