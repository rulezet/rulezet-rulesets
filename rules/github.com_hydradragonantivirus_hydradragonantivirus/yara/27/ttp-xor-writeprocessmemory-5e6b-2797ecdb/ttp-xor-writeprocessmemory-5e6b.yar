rule TTP_XOR_WriteProcessMemory_5e6b {
  strings:
    $key_5e6b = { 09 19 [2] 3b 3b [2] 3d 0e [2] 13 0e [2] 2c 12 }

  condition:
    any of them
}