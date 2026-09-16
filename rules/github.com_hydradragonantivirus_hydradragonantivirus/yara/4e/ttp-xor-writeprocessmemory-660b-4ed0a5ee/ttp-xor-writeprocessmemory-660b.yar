rule TTP_XOR_WriteProcessMemory_660b {
  strings:
    $key_660b = { 31 79 [2] 03 5b [2] 05 6e [2] 2b 6e [2] 14 72 }

  condition:
    any of them
}