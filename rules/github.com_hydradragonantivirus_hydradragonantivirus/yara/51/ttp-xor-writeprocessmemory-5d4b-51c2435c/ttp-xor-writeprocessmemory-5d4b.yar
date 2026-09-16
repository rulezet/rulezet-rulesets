rule TTP_XOR_WriteProcessMemory_5d4b {
  strings:
    $key_5d4b = { 0a 39 [2] 38 1b [2] 3e 2e [2] 10 2e [2] 2f 32 }

  condition:
    any of them
}