rule TTP_XOR_WriteProcessMemory_567b {
  strings:
    $key_567b = { 01 09 [2] 33 2b [2] 35 1e [2] 1b 1e [2] 24 02 }

  condition:
    any of them
}