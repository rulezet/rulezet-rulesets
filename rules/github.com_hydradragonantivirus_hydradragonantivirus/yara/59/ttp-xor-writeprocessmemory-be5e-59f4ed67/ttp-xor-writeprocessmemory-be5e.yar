rule TTP_XOR_WriteProcessMemory_be5e {
  strings:
    $key_be5e = { e9 2c [2] db 0e [2] dd 3b [2] f3 3b [2] cc 27 }

  condition:
    any of them
}