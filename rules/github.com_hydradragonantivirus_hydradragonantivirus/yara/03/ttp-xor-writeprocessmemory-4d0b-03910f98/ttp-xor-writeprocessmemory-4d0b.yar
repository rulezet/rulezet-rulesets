rule TTP_XOR_WriteProcessMemory_4d0b {
  strings:
    $key_4d0b = { 1a 79 [2] 28 5b [2] 2e 6e [2] 00 6e [2] 3f 72 }

  condition:
    any of them
}