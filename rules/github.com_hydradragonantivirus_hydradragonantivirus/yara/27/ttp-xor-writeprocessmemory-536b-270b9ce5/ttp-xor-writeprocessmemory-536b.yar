rule TTP_XOR_WriteProcessMemory_536b {
  strings:
    $key_536b = { 04 19 [2] 36 3b [2] 30 0e [2] 1e 0e [2] 21 12 }

  condition:
    any of them
}