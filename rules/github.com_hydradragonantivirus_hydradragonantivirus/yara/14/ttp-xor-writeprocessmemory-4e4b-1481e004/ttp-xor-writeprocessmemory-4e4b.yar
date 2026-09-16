rule TTP_XOR_WriteProcessMemory_4e4b {
  strings:
    $key_4e4b = { 19 39 [2] 2b 1b [2] 2d 2e [2] 03 2e [2] 3c 32 }

  condition:
    any of them
}