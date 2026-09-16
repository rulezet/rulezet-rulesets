rule TTP_XOR_WriteProcessMemory_be2d {
  strings:
    $key_be2d = { e9 5f [2] db 7d [2] dd 48 [2] f3 48 [2] cc 54 }

  condition:
    any of them
}