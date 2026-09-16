rule TTP_XOR_WriteProcessMemory_4e0b {
  strings:
    $key_4e0b = { 19 79 [2] 2b 5b [2] 2d 6e [2] 03 6e [2] 3c 72 }

  condition:
    any of them
}