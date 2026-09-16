rule TTP_XOR_WriteProcessMemory_742b {
  strings:
    $key_742b = { 23 59 [2] 11 7b [2] 17 4e [2] 39 4e [2] 06 52 }

  condition:
    any of them
}