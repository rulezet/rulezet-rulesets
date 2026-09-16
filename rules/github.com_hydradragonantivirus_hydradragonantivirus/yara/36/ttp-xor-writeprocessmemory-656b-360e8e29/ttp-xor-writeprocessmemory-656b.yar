rule TTP_XOR_WriteProcessMemory_656b {
  strings:
    $key_656b = { 32 19 [2] 00 3b [2] 06 0e [2] 28 0e [2] 17 12 }

  condition:
    any of them
}