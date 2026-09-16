rule TTP_XOR_WriteProcessMemory_120b {
  strings:
    $key_120b = { 45 79 [2] 77 5b [2] 71 6e [2] 5f 6e [2] 60 72 }

  condition:
    any of them
}