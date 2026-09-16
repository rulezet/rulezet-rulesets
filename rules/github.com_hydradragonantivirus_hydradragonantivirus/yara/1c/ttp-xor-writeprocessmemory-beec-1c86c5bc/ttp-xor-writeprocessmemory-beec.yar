rule TTP_XOR_WriteProcessMemory_beec {
  strings:
    $key_beec = { e9 9e [2] db bc [2] dd 89 [2] f3 89 [2] cc 95 }

  condition:
    any of them
}