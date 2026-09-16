rule TTP_XOR_WriteProcessMemory_5f7b {
  strings:
    $key_5f7b = { 08 09 [2] 3a 2b [2] 3c 1e [2] 12 1e [2] 2d 02 }

  condition:
    any of them
}