rule TTP_XOR_WriteProcessMemory_be73 {
  strings:
    $key_be73 = { e9 01 [2] db 23 [2] dd 16 [2] f3 16 [2] cc 0a }

  condition:
    any of them
}