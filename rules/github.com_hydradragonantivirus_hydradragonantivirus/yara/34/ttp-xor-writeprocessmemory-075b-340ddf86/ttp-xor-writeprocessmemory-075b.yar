rule TTP_XOR_WriteProcessMemory_075b {
  strings:
    $key_075b = { 50 29 [2] 62 0b [2] 64 3e [2] 4a 3e [2] 75 22 }

  condition:
    any of them
}