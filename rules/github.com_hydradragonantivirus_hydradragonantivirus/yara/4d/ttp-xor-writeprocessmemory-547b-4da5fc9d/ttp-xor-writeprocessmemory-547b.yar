rule TTP_XOR_WriteProcessMemory_547b {
  strings:
    $key_547b = { 03 09 [2] 31 2b [2] 37 1e [2] 19 1e [2] 26 02 }

  condition:
    any of them
}