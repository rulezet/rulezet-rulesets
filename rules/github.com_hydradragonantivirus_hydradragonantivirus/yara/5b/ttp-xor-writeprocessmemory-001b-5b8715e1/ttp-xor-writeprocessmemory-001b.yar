rule TTP_XOR_WriteProcessMemory_001b {
  strings:
    $key_001b = { 57 69 [2] 65 4b [2] 63 7e [2] 4d 7e [2] 72 62 }

  condition:
    any of them
}