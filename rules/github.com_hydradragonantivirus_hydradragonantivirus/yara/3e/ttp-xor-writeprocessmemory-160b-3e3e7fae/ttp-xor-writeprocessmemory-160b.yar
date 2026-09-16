rule TTP_XOR_WriteProcessMemory_160b {
  strings:
    $key_160b = { 41 79 [2] 73 5b [2] 75 6e [2] 5b 6e [2] 64 72 }

  condition:
    any of them
}