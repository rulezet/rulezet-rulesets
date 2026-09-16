rule TTP_XOR_WriteProcessMemory_034b {
  strings:
    $key_034b = { 54 39 [2] 66 1b [2] 60 2e [2] 4e 2e [2] 71 32 }

  condition:
    any of them
}