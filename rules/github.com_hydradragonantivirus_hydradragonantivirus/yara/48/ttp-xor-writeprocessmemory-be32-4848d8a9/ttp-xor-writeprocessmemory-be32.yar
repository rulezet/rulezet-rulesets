rule TTP_XOR_WriteProcessMemory_be32 {
  strings:
    $key_be32 = { e9 40 [2] db 62 [2] dd 57 [2] f3 57 [2] cc 4b }

  condition:
    any of them
}