rule TTP_XOR_WriteProcessMemory_6f3b {
  strings:
    $key_6f3b = { 38 49 [2] 0a 6b [2] 0c 5e [2] 22 5e [2] 1d 42 }

  condition:
    any of them
}