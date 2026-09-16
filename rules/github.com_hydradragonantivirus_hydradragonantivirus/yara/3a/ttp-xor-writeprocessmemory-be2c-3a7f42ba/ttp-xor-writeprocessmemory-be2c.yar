rule TTP_XOR_WriteProcessMemory_be2c {
  strings:
    $key_be2c = { e9 5e [2] db 7c [2] dd 49 [2] f3 49 [2] cc 55 }

  condition:
    any of them
}