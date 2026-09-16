rule TTP_XOR_WriteProcessMemory_432b {
  strings:
    $key_432b = { 14 59 [2] 26 7b [2] 20 4e [2] 0e 4e [2] 31 52 }

  condition:
    any of them
}