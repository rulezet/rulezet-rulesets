rule TTP_XOR_WriteProcessMemory_230b {
  strings:
    $key_230b = { 74 79 [2] 46 5b [2] 40 6e [2] 6e 6e [2] 51 72 }

  condition:
    any of them
}