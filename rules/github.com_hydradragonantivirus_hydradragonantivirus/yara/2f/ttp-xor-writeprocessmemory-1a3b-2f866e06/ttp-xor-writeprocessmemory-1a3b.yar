rule TTP_XOR_WriteProcessMemory_1a3b {
  strings:
    $key_1a3b = { 4d 49 [2] 7f 6b [2] 79 5e [2] 57 5e [2] 68 42 }

  condition:
    any of them
}