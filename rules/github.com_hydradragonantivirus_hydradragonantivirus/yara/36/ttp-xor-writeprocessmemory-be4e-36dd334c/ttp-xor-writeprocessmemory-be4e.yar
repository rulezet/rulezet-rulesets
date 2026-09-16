rule TTP_XOR_WriteProcessMemory_be4e {
  strings:
    $key_be4e = { e9 3c [2] db 1e [2] dd 2b [2] f3 2b [2] cc 37 }

  condition:
    any of them
}