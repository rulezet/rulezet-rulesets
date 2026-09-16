rule TTP_XOR_WriteProcessMemory_5d6b {
  strings:
    $key_5d6b = { 0a 19 [2] 38 3b [2] 3e 0e [2] 10 0e [2] 2f 12 }

  condition:
    any of them
}