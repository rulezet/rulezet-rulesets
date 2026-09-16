rule TTP_XOR_WriteProcessMemory_0b4b {
  strings:
    $key_0b4b = { 5c 39 [2] 6e 1b [2] 68 2e [2] 46 2e [2] 79 32 }

  condition:
    any of them
}