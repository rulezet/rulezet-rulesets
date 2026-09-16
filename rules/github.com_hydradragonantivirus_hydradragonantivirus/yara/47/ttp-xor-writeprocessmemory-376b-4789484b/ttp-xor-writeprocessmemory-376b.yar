rule TTP_XOR_WriteProcessMemory_376b {
  strings:
    $key_376b = { 60 19 [2] 52 3b [2] 54 0e [2] 7a 0e [2] 45 12 }

  condition:
    any of them
}