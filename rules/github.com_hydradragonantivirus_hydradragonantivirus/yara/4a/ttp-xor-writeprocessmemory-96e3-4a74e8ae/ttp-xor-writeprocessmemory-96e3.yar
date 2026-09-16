rule TTP_XOR_WriteProcessMemory_96e3 {
  strings:
    $key_96e3 = { c1 91 [2] f3 b3 [2] f5 86 [2] db 86 [2] e4 9a }

  condition:
    any of them
}