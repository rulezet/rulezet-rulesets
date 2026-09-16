rule TTP_XOR_WriteProcessMemory_4c6b {
  strings:
    $key_4c6b = { 1b 19 [2] 29 3b [2] 2f 0e [2] 01 0e [2] 3e 12 }

  condition:
    any of them
}