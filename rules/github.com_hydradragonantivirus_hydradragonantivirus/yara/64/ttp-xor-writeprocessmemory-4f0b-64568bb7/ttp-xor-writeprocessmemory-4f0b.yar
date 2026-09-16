rule TTP_XOR_WriteProcessMemory_4f0b {
  strings:
    $key_4f0b = { 18 79 [2] 2a 5b [2] 2c 6e [2] 02 6e [2] 3d 72 }

  condition:
    any of them
}