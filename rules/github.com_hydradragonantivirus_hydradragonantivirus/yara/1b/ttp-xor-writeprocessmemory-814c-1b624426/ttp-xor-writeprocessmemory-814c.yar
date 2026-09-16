rule TTP_XOR_WriteProcessMemory_814c {
  strings:
    $key_814c = { d6 3e [2] e4 1c [2] e2 29 [2] cc 29 [2] f3 35 }

  condition:
    any of them
}