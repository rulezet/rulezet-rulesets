rule TTP_XOR_WriteProcessMemory_556b {
  strings:
    $key_556b = { 02 19 [2] 30 3b [2] 36 0e [2] 18 0e [2] 27 12 }

  condition:
    any of them
}