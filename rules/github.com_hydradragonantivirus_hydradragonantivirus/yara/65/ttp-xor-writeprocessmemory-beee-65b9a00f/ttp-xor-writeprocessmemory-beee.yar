rule TTP_XOR_WriteProcessMemory_beee {
  strings:
    $key_beee = { e9 9c [2] db be [2] dd 8b [2] f3 8b [2] cc 97 }

  condition:
    any of them
}