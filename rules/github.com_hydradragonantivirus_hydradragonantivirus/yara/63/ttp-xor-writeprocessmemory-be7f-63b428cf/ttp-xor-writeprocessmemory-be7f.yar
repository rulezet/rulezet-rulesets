rule TTP_XOR_WriteProcessMemory_be7f {
  strings:
    $key_be7f = { e9 0d [2] db 2f [2] dd 1a [2] f3 1a [2] cc 06 }

  condition:
    any of them
}