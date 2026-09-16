rule TTP_XOR_WriteProcessMemory_e04b {
  strings:
    $key_e04b = { b7 39 [2] 85 1b [2] 83 2e [2] ad 2e [2] 92 32 }

  condition:
    any of them
}