rule TTP_XOR_WriteProcessMemory_be7c {
  strings:
    $key_be7c = { e9 0e [2] db 2c [2] dd 19 [2] f3 19 [2] cc 05 }

  condition:
    any of them
}