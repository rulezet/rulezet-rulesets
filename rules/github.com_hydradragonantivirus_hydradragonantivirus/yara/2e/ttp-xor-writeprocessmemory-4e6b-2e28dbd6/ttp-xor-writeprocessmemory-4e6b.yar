rule TTP_XOR_WriteProcessMemory_4e6b {
  strings:
    $key_4e6b = { 19 19 [2] 2b 3b [2] 2d 0e [2] 03 0e [2] 3c 12 }

  condition:
    any of them
}