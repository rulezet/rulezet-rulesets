rule TTP_XOR_WriteProcessMemory_be65 {
  strings:
    $key_be65 = { e9 17 [2] db 35 [2] dd 00 [2] f3 00 [2] cc 1c }

  condition:
    any of them
}