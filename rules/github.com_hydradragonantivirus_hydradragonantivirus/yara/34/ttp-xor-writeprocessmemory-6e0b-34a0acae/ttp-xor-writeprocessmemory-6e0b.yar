rule TTP_XOR_WriteProcessMemory_6e0b {
  strings:
    $key_6e0b = { 39 79 [2] 0b 5b [2] 0d 6e [2] 23 6e [2] 1c 72 }

  condition:
    any of them
}