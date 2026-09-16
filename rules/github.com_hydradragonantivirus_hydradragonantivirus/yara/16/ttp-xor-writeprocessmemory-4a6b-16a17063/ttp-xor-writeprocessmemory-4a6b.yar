rule TTP_XOR_WriteProcessMemory_4a6b {
  strings:
    $key_4a6b = { 1d 19 [2] 2f 3b [2] 29 0e [2] 07 0e [2] 38 12 }

  condition:
    any of them
}