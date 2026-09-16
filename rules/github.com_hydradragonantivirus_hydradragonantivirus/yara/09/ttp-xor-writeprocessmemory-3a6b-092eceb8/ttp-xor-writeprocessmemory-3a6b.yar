rule TTP_XOR_WriteProcessMemory_3a6b {
  strings:
    $key_3a6b = { 6d 19 [2] 5f 3b [2] 59 0e [2] 77 0e [2] 48 12 }

  condition:
    any of them
}