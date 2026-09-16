rule TTP_XOR_WriteProcessMemory_be25 {
  strings:
    $key_be25 = { e9 57 [2] db 75 [2] dd 40 [2] f3 40 [2] cc 5c }

  condition:
    any of them
}