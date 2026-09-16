rule TTP_XOR_WriteProcessMemory_772e {
  strings:
    $key_772e = { 20 5c [2] 12 7e [2] 14 4b [2] 3a 4b [2] 05 57 }

  condition:
    any of them
}