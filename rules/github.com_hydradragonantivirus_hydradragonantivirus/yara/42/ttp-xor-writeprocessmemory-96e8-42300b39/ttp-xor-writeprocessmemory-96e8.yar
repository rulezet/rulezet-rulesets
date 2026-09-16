rule TTP_XOR_WriteProcessMemory_96e8 {
  strings:
    $key_96e8 = { c1 9a [2] f3 b8 [2] f5 8d [2] db 8d [2] e4 91 }

  condition:
    any of them
}