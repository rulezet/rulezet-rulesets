rule TTP_XOR_WriteProcessMemory_056b {
  strings:
    $key_056b = { 52 19 [2] 60 3b [2] 66 0e [2] 48 0e [2] 77 12 }

  condition:
    any of them
}