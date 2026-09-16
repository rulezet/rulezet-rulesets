rule TTP_XOR_WriteProcessMemory_5f5b {
  strings:
    $key_5f5b = { 08 29 [2] 3a 0b [2] 3c 3e [2] 12 3e [2] 2d 22 }

  condition:
    any of them
}