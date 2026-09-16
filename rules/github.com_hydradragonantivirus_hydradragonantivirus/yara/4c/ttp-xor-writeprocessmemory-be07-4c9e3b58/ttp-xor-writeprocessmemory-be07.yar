rule TTP_XOR_WriteProcessMemory_be07 {
  strings:
    $key_be07 = { e9 75 [2] db 57 [2] dd 62 [2] f3 62 [2] cc 7e }

  condition:
    any of them
}