rule TTP_XOR_WriteProcessMemory_be48 {
  strings:
    $key_be48 = { e9 3a [2] db 18 [2] dd 2d [2] f3 2d [2] cc 31 }

  condition:
    any of them
}