rule TTP_XOR_WriteProcessMemory_af0b {
  strings:
    $key_af0b = { f8 79 [2] ca 5b [2] cc 6e [2] e2 6e [2] dd 72 }

  condition:
    any of them
}