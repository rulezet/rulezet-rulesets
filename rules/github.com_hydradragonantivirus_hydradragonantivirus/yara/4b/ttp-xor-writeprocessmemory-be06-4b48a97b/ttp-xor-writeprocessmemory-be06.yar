rule TTP_XOR_WriteProcessMemory_be06 {
  strings:
    $key_be06 = { e9 74 [2] db 56 [2] dd 63 [2] f3 63 [2] cc 7f }

  condition:
    any of them
}