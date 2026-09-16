rule TTP_XOR_WriteProcessMemory_614b {
  strings:
    $key_614b = { 36 39 [2] 04 1b [2] 02 2e [2] 2c 2e [2] 13 32 }

  condition:
    any of them
}