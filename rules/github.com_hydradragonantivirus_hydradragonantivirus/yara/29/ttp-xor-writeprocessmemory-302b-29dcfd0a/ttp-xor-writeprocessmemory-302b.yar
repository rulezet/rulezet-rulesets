rule TTP_XOR_WriteProcessMemory_302b {
  strings:
    $key_302b = { 67 59 [2] 55 7b [2] 53 4e [2] 7d 4e [2] 42 52 }

  condition:
    any of them
}