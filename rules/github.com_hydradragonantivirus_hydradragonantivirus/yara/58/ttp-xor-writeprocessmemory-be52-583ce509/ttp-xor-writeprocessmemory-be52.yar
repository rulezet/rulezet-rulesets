rule TTP_XOR_WriteProcessMemory_be52 {
  strings:
    $key_be52 = { e9 20 [2] db 02 [2] dd 37 [2] f3 37 [2] cc 2b }

  condition:
    any of them
}