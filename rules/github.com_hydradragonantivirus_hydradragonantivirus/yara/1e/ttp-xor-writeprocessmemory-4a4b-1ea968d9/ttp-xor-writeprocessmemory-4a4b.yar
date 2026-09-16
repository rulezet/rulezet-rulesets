rule TTP_XOR_WriteProcessMemory_4a4b {
  strings:
    $key_4a4b = { 1d 39 [2] 2f 1b [2] 29 2e [2] 07 2e [2] 38 32 }

  condition:
    any of them
}