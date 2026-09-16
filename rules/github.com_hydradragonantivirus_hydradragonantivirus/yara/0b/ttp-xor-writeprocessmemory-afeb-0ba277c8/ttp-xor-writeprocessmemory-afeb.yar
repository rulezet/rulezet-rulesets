rule TTP_XOR_WriteProcessMemory_afeb {
  strings:
    $key_afeb = { f8 99 [2] ca bb [2] cc 8e [2] e2 8e [2] dd 92 }

  condition:
    any of them
}