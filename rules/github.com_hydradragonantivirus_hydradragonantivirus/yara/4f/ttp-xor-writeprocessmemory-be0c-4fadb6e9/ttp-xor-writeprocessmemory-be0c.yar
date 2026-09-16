rule TTP_XOR_WriteProcessMemory_be0c {
  strings:
    $key_be0c = { e9 7e [2] db 5c [2] dd 69 [2] f3 69 [2] cc 75 }

  condition:
    any of them
}