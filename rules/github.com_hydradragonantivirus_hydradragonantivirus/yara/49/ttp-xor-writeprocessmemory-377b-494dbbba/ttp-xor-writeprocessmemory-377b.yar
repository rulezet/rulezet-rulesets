rule TTP_XOR_WriteProcessMemory_377b {
  strings:
    $key_377b = { 60 09 [2] 52 2b [2] 54 1e [2] 7a 1e [2] 45 02 }

  condition:
    any of them
}