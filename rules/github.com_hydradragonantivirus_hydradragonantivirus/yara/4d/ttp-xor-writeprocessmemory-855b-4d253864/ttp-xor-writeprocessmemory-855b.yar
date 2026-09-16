rule TTP_XOR_WriteProcessMemory_855b {
  strings:
    $key_855b = { d2 29 [2] e0 0b [2] e6 3e [2] c8 3e [2] f7 22 }

  condition:
    any of them
}