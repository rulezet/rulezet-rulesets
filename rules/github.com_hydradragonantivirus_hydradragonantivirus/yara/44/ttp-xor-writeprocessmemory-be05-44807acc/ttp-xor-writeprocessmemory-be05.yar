rule TTP_XOR_WriteProcessMemory_be05 {
  strings:
    $key_be05 = { e9 77 [2] db 55 [2] dd 60 [2] f3 60 [2] cc 7c }

  condition:
    any of them
}