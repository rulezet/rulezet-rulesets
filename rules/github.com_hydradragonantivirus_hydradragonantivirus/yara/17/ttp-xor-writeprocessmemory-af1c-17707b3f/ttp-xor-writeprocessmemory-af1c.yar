rule TTP_XOR_WriteProcessMemory_af1c {
  strings:
    $key_af1c = { f8 6e [2] ca 4c [2] cc 79 [2] e2 79 [2] dd 65 }

  condition:
    any of them
}