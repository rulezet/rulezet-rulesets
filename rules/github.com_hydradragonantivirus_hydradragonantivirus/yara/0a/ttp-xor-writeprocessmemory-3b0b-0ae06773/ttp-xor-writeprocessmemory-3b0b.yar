rule TTP_XOR_WriteProcessMemory_3b0b {
  strings:
    $key_3b0b = { 6c 79 [2] 5e 5b [2] 58 6e [2] 76 6e [2] 49 72 }

  condition:
    any of them
}