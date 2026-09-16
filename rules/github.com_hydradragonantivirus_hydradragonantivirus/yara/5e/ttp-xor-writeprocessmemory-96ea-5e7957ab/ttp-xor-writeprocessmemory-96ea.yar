rule TTP_XOR_WriteProcessMemory_96ea {
  strings:
    $key_96ea = { c1 98 [2] f3 ba [2] f5 8f [2] db 8f [2] e4 93 }

  condition:
    any of them
}