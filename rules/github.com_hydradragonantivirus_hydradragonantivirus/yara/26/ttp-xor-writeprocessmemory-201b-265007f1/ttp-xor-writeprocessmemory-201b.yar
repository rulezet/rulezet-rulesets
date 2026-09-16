rule TTP_XOR_WriteProcessMemory_201b {
  strings:
    $key_201b = { 77 69 [2] 45 4b [2] 43 7e [2] 6d 7e [2] 52 62 }

  condition:
    any of them
}