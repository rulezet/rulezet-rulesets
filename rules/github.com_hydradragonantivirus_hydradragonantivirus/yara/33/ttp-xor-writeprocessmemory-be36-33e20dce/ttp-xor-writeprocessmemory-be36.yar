rule TTP_XOR_WriteProcessMemory_be36 {
  strings:
    $key_be36 = { e9 44 [2] db 66 [2] dd 53 [2] f3 53 [2] cc 4f }

  condition:
    any of them
}