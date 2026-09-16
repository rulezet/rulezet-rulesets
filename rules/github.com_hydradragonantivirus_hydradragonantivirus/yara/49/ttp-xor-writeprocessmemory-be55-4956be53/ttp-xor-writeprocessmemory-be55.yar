rule TTP_XOR_WriteProcessMemory_be55 {
  strings:
    $key_be55 = { e9 27 [2] db 05 [2] dd 30 [2] f3 30 [2] cc 2c }

  condition:
    any of them
}