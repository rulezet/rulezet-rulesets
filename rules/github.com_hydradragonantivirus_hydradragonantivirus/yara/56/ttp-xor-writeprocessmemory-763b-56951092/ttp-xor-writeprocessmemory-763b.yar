rule TTP_XOR_WriteProcessMemory_763b {
  strings:
    $key_763b = { 21 49 [2] 13 6b [2] 15 5e [2] 3b 5e [2] 04 42 }

  condition:
    any of them
}