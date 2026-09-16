rule TTP_XOR_WriteProcessMemory_7d5b {
  strings:
    $key_7d5b = { 2a 29 [2] 18 0b [2] 1e 3e [2] 30 3e [2] 0f 22 }

  condition:
    any of them
}