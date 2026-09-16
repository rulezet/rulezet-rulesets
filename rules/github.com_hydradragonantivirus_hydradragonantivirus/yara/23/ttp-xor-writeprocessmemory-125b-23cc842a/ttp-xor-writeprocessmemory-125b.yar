rule TTP_XOR_WriteProcessMemory_125b {
  strings:
    $key_125b = { 45 29 [2] 77 0b [2] 71 3e [2] 5f 3e [2] 60 22 }

  condition:
    any of them
}