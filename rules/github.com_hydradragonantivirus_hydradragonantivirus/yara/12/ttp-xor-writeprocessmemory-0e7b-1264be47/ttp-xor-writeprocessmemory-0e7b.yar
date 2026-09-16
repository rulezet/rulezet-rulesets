rule TTP_XOR_WriteProcessMemory_0e7b {
  strings:
    $key_0e7b = { 59 09 [2] 6b 2b [2] 6d 1e [2] 43 1e [2] 7c 02 }

  condition:
    any of them
}