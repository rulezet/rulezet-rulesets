rule TTP_XOR_WriteProcessMemory_af5c {
  strings:
    $key_af5c = { f8 2e [2] ca 0c [2] cc 39 [2] e2 39 [2] dd 25 }

  condition:
    any of them
}