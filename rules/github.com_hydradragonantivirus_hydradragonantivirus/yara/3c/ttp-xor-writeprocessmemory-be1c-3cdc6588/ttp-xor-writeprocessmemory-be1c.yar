rule TTP_XOR_WriteProcessMemory_be1c {
  strings:
    $key_be1c = { e9 6e [2] db 4c [2] dd 79 [2] f3 79 [2] cc 65 }

  condition:
    any of them
}