rule TTP_XOR_WriteProcessMemory_196b {
  strings:
    $key_196b = { 4e 19 [2] 7c 3b [2] 7a 0e [2] 54 0e [2] 6b 12 }

  condition:
    any of them
}