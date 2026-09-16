rule TTP_XOR_WriteProcessMemory_3c4b {
  strings:
    $key_3c4b = { 6b 39 [2] 59 1b [2] 5f 2e [2] 71 2e [2] 4e 32 }

  condition:
    any of them
}