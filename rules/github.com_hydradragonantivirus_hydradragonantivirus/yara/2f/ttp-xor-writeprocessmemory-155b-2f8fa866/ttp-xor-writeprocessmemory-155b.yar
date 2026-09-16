rule TTP_XOR_WriteProcessMemory_155b {
  strings:
    $key_155b = { 42 29 [2] 70 0b [2] 76 3e [2] 58 3e [2] 67 22 }

  condition:
    any of them
}