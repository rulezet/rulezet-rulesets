rule TTP_XOR_WriteProcessMemory_be23 {
  strings:
    $key_be23 = { e9 51 [2] db 73 [2] dd 46 [2] f3 46 [2] cc 5a }

  condition:
    any of them
}