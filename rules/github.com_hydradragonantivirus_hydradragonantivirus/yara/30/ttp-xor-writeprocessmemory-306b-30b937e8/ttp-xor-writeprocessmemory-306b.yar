rule TTP_XOR_WriteProcessMemory_306b {
  strings:
    $key_306b = { 67 19 [2] 55 3b [2] 53 0e [2] 7d 0e [2] 42 12 }

  condition:
    any of them
}