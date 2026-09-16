rule TTP_XOR_WriteProcessMemory_be71 {
  strings:
    $key_be71 = { e9 03 [2] db 21 [2] dd 14 [2] f3 14 [2] cc 08 }

  condition:
    any of them
}