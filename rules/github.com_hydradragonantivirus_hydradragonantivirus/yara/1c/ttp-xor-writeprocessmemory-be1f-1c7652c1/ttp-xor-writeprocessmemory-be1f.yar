rule TTP_XOR_WriteProcessMemory_be1f {
  strings:
    $key_be1f = { e9 6d [2] db 4f [2] dd 7a [2] f3 7a [2] cc 66 }

  condition:
    any of them
}