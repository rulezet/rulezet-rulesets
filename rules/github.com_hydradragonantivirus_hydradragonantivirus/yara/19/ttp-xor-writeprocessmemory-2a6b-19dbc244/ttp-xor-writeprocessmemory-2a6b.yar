rule TTP_XOR_WriteProcessMemory_2a6b {
  strings:
    $key_2a6b = { 7d 19 [2] 4f 3b [2] 49 0e [2] 67 0e [2] 58 12 }

  condition:
    any of them
}