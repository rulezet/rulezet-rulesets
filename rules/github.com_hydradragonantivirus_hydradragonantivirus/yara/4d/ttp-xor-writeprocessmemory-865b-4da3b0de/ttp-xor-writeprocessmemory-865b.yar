rule TTP_XOR_WriteProcessMemory_865b {
  strings:
    $key_865b = { d1 29 [2] e3 0b [2] e5 3e [2] cb 3e [2] f4 22 }

  condition:
    any of them
}