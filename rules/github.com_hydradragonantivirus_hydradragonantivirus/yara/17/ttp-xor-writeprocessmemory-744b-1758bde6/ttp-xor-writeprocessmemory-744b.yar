rule TTP_XOR_WriteProcessMemory_744b {
  strings:
    $key_744b = { 23 39 [2] 11 1b [2] 17 2e [2] 39 2e [2] 06 32 }

  condition:
    any of them
}