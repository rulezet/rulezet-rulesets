rule TTP_XOR_WriteProcessMemory_be31 {
  strings:
    $key_be31 = { e9 43 [2] db 61 [2] dd 54 [2] f3 54 [2] cc 48 }

  condition:
    any of them
}