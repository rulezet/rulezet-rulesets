rule TTP_XOR_WriteProcessMemory_777b {
  strings:
    $key_777b = { 20 09 [2] 12 2b [2] 14 1e [2] 3a 1e [2] 05 02 }

  condition:
    any of them
}