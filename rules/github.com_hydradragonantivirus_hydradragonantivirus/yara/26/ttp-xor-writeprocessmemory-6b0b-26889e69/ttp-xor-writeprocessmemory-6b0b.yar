rule TTP_XOR_WriteProcessMemory_6b0b {
  strings:
    $key_6b0b = { 3c 79 [2] 0e 5b [2] 08 6e [2] 26 6e [2] 19 72 }

  condition:
    any of them
}