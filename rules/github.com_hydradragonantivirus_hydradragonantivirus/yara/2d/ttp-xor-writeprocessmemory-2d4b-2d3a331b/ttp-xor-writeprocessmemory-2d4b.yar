rule TTP_XOR_WriteProcessMemory_2d4b {
  strings:
    $key_2d4b = { 7a 39 [2] 48 1b [2] 4e 2e [2] 60 2e [2] 5f 32 }

  condition:
    any of them
}