rule TTP_XOR_WriteProcessMemory_be2a {
  strings:
    $key_be2a = { e9 58 [2] db 7a [2] dd 4f [2] f3 4f [2] cc 53 }

  condition:
    any of them
}