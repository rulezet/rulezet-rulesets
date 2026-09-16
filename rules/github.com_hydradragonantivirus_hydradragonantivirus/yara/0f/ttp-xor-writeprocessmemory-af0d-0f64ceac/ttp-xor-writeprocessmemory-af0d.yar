rule TTP_XOR_WriteProcessMemory_af0d {
  strings:
    $key_af0d = { f8 7f [2] ca 5d [2] cc 68 [2] e2 68 [2] dd 74 }

  condition:
    any of them
}