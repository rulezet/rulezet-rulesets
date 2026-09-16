rule TTP_XOR_WriteProcessMemory_be62 {
  strings:
    $key_be62 = { e9 10 [2] db 32 [2] dd 07 [2] f3 07 [2] cc 1b }

  condition:
    any of them
}