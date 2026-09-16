rule TTP_XOR_WriteProcessMemory_be22 {
  strings:
    $key_be22 = { e9 50 [2] db 72 [2] dd 47 [2] f3 47 [2] cc 5b }

  condition:
    any of them
}