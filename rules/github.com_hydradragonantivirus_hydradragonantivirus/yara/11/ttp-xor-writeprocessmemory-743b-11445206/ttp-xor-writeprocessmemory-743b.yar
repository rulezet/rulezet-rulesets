rule TTP_XOR_WriteProcessMemory_743b {
  strings:
    $key_743b = { 23 49 [2] 11 6b [2] 17 5e [2] 39 5e [2] 06 42 }

  condition:
    any of them
}