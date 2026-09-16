rule TTP_XOR_WriteProcessMemory_1d0b {
  strings:
    $key_1d0b = { 4a 79 [2] 78 5b [2] 7e 6e [2] 50 6e [2] 6f 72 }

  condition:
    any of them
}