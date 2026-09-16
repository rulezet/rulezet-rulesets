rule TTP_XOR_WriteProcessMemory_be0f {
  strings:
    $key_be0f = { e9 7d [2] db 5f [2] dd 6a [2] f3 6a [2] cc 76 }

  condition:
    any of them
}