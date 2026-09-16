rule TTP_XOR_WriteProcessMemory_be33 {
  strings:
    $key_be33 = { e9 41 [2] db 63 [2] dd 56 [2] f3 56 [2] cc 4a }

  condition:
    any of them
}