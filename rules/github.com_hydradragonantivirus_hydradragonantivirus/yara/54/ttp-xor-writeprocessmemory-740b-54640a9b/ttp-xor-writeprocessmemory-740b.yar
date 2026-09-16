rule TTP_XOR_WriteProcessMemory_740b {
  strings:
    $key_740b = { 23 79 [2] 11 5b [2] 17 6e [2] 39 6e [2] 06 72 }

  condition:
    any of them
}