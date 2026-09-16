rule TTP_XOR_WriteProcessMemory_af7d {
  strings:
    $key_af7d = { f8 0f [2] ca 2d [2] cc 18 [2] e2 18 [2] dd 04 }

  condition:
    any of them
}