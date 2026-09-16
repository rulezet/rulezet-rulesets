rule TTP_XOR_WriteProcessMemory_be4a {
  strings:
    $key_be4a = { e9 38 [2] db 1a [2] dd 2f [2] f3 2f [2] cc 33 }

  condition:
    any of them
}