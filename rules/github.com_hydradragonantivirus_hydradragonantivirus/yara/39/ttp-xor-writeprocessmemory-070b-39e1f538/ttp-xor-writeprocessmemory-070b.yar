rule TTP_XOR_WriteProcessMemory_070b {
  strings:
    $key_070b = { 50 79 [2] 62 5b [2] 64 6e [2] 4a 6e [2] 75 72 }

  condition:
    any of them
}