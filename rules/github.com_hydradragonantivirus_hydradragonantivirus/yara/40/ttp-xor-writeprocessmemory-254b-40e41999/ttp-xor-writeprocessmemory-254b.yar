rule TTP_XOR_WriteProcessMemory_254b {
  strings:
    $key_254b = { 72 39 [2] 40 1b [2] 46 2e [2] 68 2e [2] 57 32 }

  condition:
    any of them
}