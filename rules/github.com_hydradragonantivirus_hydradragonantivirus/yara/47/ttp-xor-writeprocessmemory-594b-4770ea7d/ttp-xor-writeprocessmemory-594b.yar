rule TTP_XOR_WriteProcessMemory_594b {
  strings:
    $key_594b = { 0e 39 [2] 3c 1b [2] 3a 2e [2] 14 2e [2] 2b 32 }

  condition:
    any of them
}