rule TTP_XOR_WriteProcessMemory_073b {
  strings:
    $key_073b = { 50 49 [2] 62 6b [2] 64 5e [2] 4a 5e [2] 75 42 }

  condition:
    any of them
}