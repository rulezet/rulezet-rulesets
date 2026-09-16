rule TTP_XOR_WriteProcessMemory_123c {
  strings:
    $key_123c = { 45 4e [2] 77 6c [2] 71 59 [2] 5f 59 [2] 60 45 }

  condition:
    any of them
}