rule TTP_XOR_WriteProcessMemory_be0a {
  strings:
    $key_be0a = { e9 78 [2] db 5a [2] dd 6f [2] f3 6f [2] cc 73 }

  condition:
    any of them
}