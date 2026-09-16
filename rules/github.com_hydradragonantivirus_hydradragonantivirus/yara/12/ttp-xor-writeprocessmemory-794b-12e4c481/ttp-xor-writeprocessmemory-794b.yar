rule TTP_XOR_WriteProcessMemory_794b {
  strings:
    $key_794b = { 2e 39 [2] 1c 1b [2] 1a 2e [2] 34 2e [2] 0b 32 }

  condition:
    any of them
}