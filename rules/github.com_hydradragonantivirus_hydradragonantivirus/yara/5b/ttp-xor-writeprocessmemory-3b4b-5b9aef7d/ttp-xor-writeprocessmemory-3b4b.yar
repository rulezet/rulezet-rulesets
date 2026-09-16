rule TTP_XOR_WriteProcessMemory_3b4b {
  strings:
    $key_3b4b = { 6c 39 [2] 5e 1b [2] 58 2e [2] 76 2e [2] 49 32 }

  condition:
    any of them
}