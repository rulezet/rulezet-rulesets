rule TTP_XOR_WriteProcessMemory_5b3b {
  strings:
    $key_5b3b = { 0c 49 [2] 3e 6b [2] 38 5e [2] 16 5e [2] 29 42 }

  condition:
    any of them
}