rule TTP_XOR_WriteProcessMemory_be6c {
  strings:
    $key_be6c = { e9 1e [2] db 3c [2] dd 09 [2] f3 09 [2] cc 15 }

  condition:
    any of them
}