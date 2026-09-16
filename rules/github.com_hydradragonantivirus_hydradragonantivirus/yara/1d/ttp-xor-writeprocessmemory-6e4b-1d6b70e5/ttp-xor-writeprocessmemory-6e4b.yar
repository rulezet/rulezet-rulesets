rule TTP_XOR_WriteProcessMemory_6e4b {
  strings:
    $key_6e4b = { 39 39 [2] 0b 1b [2] 0d 2e [2] 23 2e [2] 1c 32 }

  condition:
    any of them
}