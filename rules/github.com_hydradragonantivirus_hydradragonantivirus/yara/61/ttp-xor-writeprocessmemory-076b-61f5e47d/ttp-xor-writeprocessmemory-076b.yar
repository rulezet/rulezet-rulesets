rule TTP_XOR_WriteProcessMemory_076b {
  strings:
    $key_076b = { 50 19 [2] 62 3b [2] 64 0e [2] 4a 0e [2] 75 12 }

  condition:
    any of them
}