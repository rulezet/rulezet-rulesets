rule TTP_XOR_WriteProcessMemory_5e5b {
  strings:
    $key_5e5b = { 09 29 [2] 3b 0b [2] 3d 3e [2] 13 3e [2] 2c 22 }

  condition:
    any of them
}