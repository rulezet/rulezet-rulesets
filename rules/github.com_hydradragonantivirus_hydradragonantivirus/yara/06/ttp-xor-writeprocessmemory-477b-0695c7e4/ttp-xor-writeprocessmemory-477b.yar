rule TTP_XOR_WriteProcessMemory_477b {
  strings:
    $key_477b = { 10 09 [2] 22 2b [2] 24 1e [2] 0a 1e [2] 35 02 }

  condition:
    any of them
}