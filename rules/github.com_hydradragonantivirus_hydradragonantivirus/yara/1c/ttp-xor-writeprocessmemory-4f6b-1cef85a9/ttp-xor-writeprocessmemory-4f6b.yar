rule TTP_XOR_WriteProcessMemory_4f6b {
  strings:
    $key_4f6b = { 18 19 [2] 2a 3b [2] 2c 0e [2] 02 0e [2] 3d 12 }

  condition:
    any of them
}