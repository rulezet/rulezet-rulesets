rule TTP_XOR_WriteProcessMemory_be54 {
  strings:
    $key_be54 = { e9 26 [2] db 04 [2] dd 31 [2] f3 31 [2] cc 2d }

  condition:
    any of them
}