rule TTP_XOR_WriteProcessMemory_423b {
  strings:
    $key_423b = { 15 49 [2] 27 6b [2] 21 5e [2] 0f 5e [2] 30 42 }

  condition:
    any of them
}