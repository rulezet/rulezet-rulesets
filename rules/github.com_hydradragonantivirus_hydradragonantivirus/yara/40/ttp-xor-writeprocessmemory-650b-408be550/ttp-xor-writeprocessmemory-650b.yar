rule TTP_XOR_WriteProcessMemory_650b {
  strings:
    $key_650b = { 32 79 [2] 00 5b [2] 06 6e [2] 28 6e [2] 17 72 }

  condition:
    any of them
}