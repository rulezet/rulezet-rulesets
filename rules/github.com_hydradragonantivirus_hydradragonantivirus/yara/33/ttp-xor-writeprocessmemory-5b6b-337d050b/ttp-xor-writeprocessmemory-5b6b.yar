rule TTP_XOR_WriteProcessMemory_5b6b {
  strings:
    $key_5b6b = { 0c 19 [2] 3e 3b [2] 38 0e [2] 16 0e [2] 29 12 }

  condition:
    any of them
}