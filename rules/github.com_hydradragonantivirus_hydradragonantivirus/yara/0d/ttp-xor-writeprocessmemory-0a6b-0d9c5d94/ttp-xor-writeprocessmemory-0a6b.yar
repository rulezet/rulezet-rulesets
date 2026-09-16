rule TTP_XOR_WriteProcessMemory_0a6b {
  strings:
    $key_0a6b = { 5d 19 [2] 6f 3b [2] 69 0e [2] 47 0e [2] 78 12 }

  condition:
    any of them
}