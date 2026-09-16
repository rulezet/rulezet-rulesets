rule TTP_XOR_WriteProcessMemory_6d4b {
  strings:
    $key_6d4b = { 3a 39 [2] 08 1b [2] 0e 2e [2] 20 2e [2] 1f 32 }

  condition:
    any of them
}