rule TTP_XOR_WriteProcessMemory_473b {
  strings:
    $key_473b = { 10 49 [2] 22 6b [2] 24 5e [2] 0a 5e [2] 35 42 }

  condition:
    any of them
}