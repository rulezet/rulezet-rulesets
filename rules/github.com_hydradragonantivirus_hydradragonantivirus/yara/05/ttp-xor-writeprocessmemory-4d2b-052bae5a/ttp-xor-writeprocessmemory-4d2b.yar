rule TTP_XOR_WriteProcessMemory_4d2b {
  strings:
    $key_4d2b = { 1a 59 [2] 28 7b [2] 2e 4e [2] 00 4e [2] 3f 52 }

  condition:
    any of them
}