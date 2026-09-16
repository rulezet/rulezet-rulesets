rule TTP_XOR_WriteProcessMemory_130b {
  strings:
    $key_130b = { 44 79 [2] 76 5b [2] 70 6e [2] 5e 6e [2] 61 72 }

  condition:
    any of them
}