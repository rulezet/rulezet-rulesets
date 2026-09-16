rule TTP_XOR_WriteProcessMemory_790b {
  strings:
    $key_790b = { 2e 79 [2] 1c 5b [2] 1a 6e [2] 34 6e [2] 0b 72 }

  condition:
    any of them
}