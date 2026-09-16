rule TTP_XOR_WriteProcessMemory_be18 {
  strings:
    $key_be18 = { e9 6a [2] db 48 [2] dd 7d [2] f3 7d [2] cc 61 }

  condition:
    any of them
}