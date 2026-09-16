rule TTP_XOR_WriteProcessMemory_e00b {
  strings:
    $key_e00b = { b7 79 [2] 85 5b [2] 83 6e [2] ad 6e [2] 92 72 }

  condition:
    any of them
}