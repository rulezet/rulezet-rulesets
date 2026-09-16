rule TTP_XOR_WriteProcessMemory_303b {
  strings:
    $key_303b = { 67 49 [2] 55 6b [2] 53 5e [2] 7d 5e [2] 42 42 }

  condition:
    any of them
}