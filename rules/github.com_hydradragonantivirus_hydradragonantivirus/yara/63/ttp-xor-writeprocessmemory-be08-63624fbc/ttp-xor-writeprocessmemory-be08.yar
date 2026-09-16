rule TTP_XOR_WriteProcessMemory_be08 {
  strings:
    $key_be08 = { e9 7a [2] db 58 [2] dd 6d [2] f3 6d [2] cc 71 }

  condition:
    any of them
}