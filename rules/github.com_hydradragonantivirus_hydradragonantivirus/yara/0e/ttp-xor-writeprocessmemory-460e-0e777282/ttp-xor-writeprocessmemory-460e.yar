rule TTP_XOR_WriteProcessMemory_460e {
  strings:
    $key_460e = { 11 7c [2] 23 5e [2] 25 6b [2] 0b 6b [2] 34 77 }

  condition:
    any of them
}