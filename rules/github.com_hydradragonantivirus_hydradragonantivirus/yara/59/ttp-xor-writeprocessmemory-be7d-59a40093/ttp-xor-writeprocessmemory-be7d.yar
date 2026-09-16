rule TTP_XOR_WriteProcessMemory_be7d {
  strings:
    $key_be7d = { e9 0f [2] db 2d [2] dd 18 [2] f3 18 [2] cc 04 }

  condition:
    any of them
}