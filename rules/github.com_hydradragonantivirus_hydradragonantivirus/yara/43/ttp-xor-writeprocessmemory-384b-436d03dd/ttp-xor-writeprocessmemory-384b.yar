rule TTP_XOR_WriteProcessMemory_384b {
  strings:
    $key_384b = { 6f 39 [2] 5d 1b [2] 5b 2e [2] 75 2e [2] 4a 32 }

  condition:
    any of them
}