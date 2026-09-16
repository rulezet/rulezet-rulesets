rule TTP_XOR_WriteProcessMemory_be20 {
  strings:
    $key_be20 = { e9 52 [2] db 70 [2] dd 45 [2] f3 45 [2] cc 59 }

  condition:
    any of them
}