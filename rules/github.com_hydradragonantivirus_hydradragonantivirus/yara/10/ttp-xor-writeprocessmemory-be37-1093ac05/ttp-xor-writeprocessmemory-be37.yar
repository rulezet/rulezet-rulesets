rule TTP_XOR_WriteProcessMemory_be37 {
  strings:
    $key_be37 = { e9 45 [2] db 67 [2] dd 52 [2] f3 52 [2] cc 4e }

  condition:
    any of them
}