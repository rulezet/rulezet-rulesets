rule TTP_XOR_WriteProcessMemory_3a0b {
  strings:
    $key_3a0b = { 6d 79 [2] 5f 5b [2] 59 6e [2] 77 6e [2] 48 72 }

  condition:
    any of them
}