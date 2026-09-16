rule TTP_XOR_WriteProcessMemory_7e6b {
  strings:
    $key_7e6b = { 29 19 [2] 1b 3b [2] 1d 0e [2] 33 0e [2] 0c 12 }

  condition:
    any of them
}