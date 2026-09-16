rule TTP_XOR_WriteProcessMemory_be17 {
  strings:
    $key_be17 = { e9 65 [2] db 47 [2] dd 72 [2] f3 72 [2] cc 6e }

  condition:
    any of them
}