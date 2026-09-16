rule TTP_XOR_WriteProcessMemory_123e {
  strings:
    $key_123e = { 45 4c [2] 77 6e [2] 71 5b [2] 5f 5b [2] 60 47 }

  condition:
    any of them
}