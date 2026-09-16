rule TTP_XOR_WriteProcessMemory_beea {
  strings:
    $key_beea = { e9 98 [2] db ba [2] dd 8f [2] f3 8f [2] cc 93 }

  condition:
    any of them
}