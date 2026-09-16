rule TTP_XOR_WriteProcessMemory_490b {
  strings:
    $key_490b = { 1e 79 [2] 2c 5b [2] 2a 6e [2] 04 6e [2] 3b 72 }

  condition:
    any of them
}