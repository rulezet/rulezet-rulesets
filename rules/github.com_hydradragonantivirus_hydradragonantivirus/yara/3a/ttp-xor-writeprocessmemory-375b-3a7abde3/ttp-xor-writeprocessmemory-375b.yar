rule TTP_XOR_WriteProcessMemory_375b {
  strings:
    $key_375b = { 60 29 [2] 52 0b [2] 54 3e [2] 7a 3e [2] 45 22 }

  condition:
    any of them
}