rule TTP_XOR_WriteProcessMemory_be3e {
  strings:
    $key_be3e = { e9 4c [2] db 6e [2] dd 5b [2] f3 5b [2] cc 47 }

  condition:
    any of them
}