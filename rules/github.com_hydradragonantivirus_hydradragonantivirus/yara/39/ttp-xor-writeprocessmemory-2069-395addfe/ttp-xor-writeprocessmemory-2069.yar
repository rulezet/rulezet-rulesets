rule TTP_XOR_WriteProcessMemory_2069 {
  strings:
    $key_2069 = { 77 1b [2] 45 39 [2] 43 0c [2] 6d 0c [2] 52 10 }

  condition:
    any of them
}