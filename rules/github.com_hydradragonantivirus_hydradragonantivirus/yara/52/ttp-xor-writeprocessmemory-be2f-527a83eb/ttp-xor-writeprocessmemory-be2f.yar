rule TTP_XOR_WriteProcessMemory_be2f {
  strings:
    $key_be2f = { e9 5d [2] db 7f [2] dd 4a [2] f3 4a [2] cc 56 }

  condition:
    any of them
}