rule TTP_XOR_WriteProcessMemory_356b {
  strings:
    $key_356b = { 62 19 [2] 50 3b [2] 56 0e [2] 78 0e [2] 47 12 }

  condition:
    any of them
}