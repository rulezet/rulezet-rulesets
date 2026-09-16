rule TTP_XOR_WriteProcessMemory_7b4b {
  strings:
    $key_7b4b = { 2c 39 [2] 1e 1b [2] 18 2e [2] 36 2e [2] 09 32 }

  condition:
    any of them
}