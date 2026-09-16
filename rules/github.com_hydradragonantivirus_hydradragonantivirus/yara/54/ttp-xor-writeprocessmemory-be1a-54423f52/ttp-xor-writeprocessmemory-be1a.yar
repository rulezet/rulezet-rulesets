rule TTP_XOR_WriteProcessMemory_be1a {
  strings:
    $key_be1a = { e9 68 [2] db 4a [2] dd 7f [2] f3 7f [2] cc 63 }

  condition:
    any of them
}