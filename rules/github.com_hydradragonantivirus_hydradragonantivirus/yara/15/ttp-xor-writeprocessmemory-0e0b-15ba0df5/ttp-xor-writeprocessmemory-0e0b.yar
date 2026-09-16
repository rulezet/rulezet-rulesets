rule TTP_XOR_WriteProcessMemory_0e0b {
  strings:
    $key_0e0b = { 59 79 [2] 6b 5b [2] 6d 6e [2] 43 6e [2] 7c 72 }

  condition:
    any of them
}