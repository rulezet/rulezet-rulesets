rule TTP_XOR_WriteProcessMemory_be77 {
  strings:
    $key_be77 = { e9 05 [2] db 27 [2] dd 12 [2] f3 12 [2] cc 0e }

  condition:
    any of them
}