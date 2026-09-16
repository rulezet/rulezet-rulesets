rule TTP_XOR_WriteProcessMemory_3c6b {
  strings:
    $key_3c6b = { 6b 19 [2] 59 3b [2] 5f 0e [2] 71 0e [2] 4e 12 }

  condition:
    any of them
}