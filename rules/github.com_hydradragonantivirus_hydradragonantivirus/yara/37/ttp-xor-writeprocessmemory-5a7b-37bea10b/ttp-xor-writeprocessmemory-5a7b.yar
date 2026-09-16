rule TTP_XOR_WriteProcessMemory_5a7b {
  strings:
    $key_5a7b = { 0d 09 [2] 3f 2b [2] 39 1e [2] 17 1e [2] 28 02 }

  condition:
    any of them
}