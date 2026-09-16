rule TTP_XOR_WriteProcessMemory_484b {
  strings:
    $key_484b = { 1f 39 [2] 2d 1b [2] 2b 2e [2] 05 2e [2] 3a 32 }

  condition:
    any of them
}