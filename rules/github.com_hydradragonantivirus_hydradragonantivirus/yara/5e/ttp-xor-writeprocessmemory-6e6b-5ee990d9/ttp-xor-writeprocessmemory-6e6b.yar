rule TTP_XOR_WriteProcessMemory_6e6b {
  strings:
    $key_6e6b = { 39 19 [2] 0b 3b [2] 0d 0e [2] 23 0e [2] 1c 12 }

  condition:
    any of them
}