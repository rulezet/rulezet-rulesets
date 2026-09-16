rule TTP_XOR_WriteProcessMemory_4d6b {
  strings:
    $key_4d6b = { 1a 19 [2] 28 3b [2] 2e 0e [2] 00 0e [2] 3f 12 }

  condition:
    any of them
}