rule TTP_XOR_WriteProcessMemory_153b {
  strings:
    $key_153b = { 42 49 [2] 70 6b [2] 76 5e [2] 58 5e [2] 67 42 }

  condition:
    any of them
}