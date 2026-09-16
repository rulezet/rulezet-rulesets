rule TTP_XOR_WriteProcessMemory_607b {
  strings:
    $key_607b = { 37 09 [2] 05 2b [2] 03 1e [2] 2d 1e [2] 12 02 }

  condition:
    any of them
}