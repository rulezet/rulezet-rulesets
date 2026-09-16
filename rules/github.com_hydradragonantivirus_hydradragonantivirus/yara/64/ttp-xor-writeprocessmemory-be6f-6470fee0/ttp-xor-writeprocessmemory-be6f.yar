rule TTP_XOR_WriteProcessMemory_be6f {
  strings:
    $key_be6f = { e9 1d [2] db 3f [2] dd 0a [2] f3 0a [2] cc 16 }

  condition:
    any of them
}