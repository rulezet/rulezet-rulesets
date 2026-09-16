rule TTP_XOR_WriteProcessMemory_5f3b {
  strings:
    $key_5f3b = { 08 49 [2] 3a 6b [2] 3c 5e [2] 12 5e [2] 2d 42 }

  condition:
    any of them
}