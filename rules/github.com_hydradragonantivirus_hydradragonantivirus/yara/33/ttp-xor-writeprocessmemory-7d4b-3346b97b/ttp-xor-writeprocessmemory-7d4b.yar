rule TTP_XOR_WriteProcessMemory_7d4b {
  strings:
    $key_7d4b = { 2a 39 [2] 18 1b [2] 1e 2e [2] 30 2e [2] 0f 32 }

  condition:
    any of them
}