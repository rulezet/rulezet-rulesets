rule TTP_XOR_WriteProcessMemory_7b6b {
  strings:
    $key_7b6b = { 2c 19 [2] 1e 3b [2] 18 0e [2] 36 0e [2] 09 12 }

  condition:
    any of them
}