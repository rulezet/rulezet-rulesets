rule TTP_XOR_WriteProcessMemory_150b {
  strings:
    $key_150b = { 42 79 [2] 70 5b [2] 76 6e [2] 58 6e [2] 67 72 }

  condition:
    any of them
}