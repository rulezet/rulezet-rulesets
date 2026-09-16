rule TTP_XOR_WriteProcessMemory_be53 {
  strings:
    $key_be53 = { e9 21 [2] db 03 [2] dd 36 [2] f3 36 [2] cc 2a }

  condition:
    any of them
}