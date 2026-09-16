rule TTP_XOR_WriteProcessMemory_5c7b {
  strings:
    $key_5c7b = { 0b 09 [2] 39 2b [2] 3f 1e [2] 11 1e [2] 2e 02 }

  condition:
    any of them
}