rule TTP_XOR_WriteProcessMemory_634b {
  strings:
    $key_634b = { 34 39 [2] 06 1b [2] 00 2e [2] 2e 2e [2] 11 32 }

  condition:
    any of them
}