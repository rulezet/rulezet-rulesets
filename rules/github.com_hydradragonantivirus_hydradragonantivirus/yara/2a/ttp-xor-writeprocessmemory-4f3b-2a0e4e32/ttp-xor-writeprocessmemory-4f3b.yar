rule TTP_XOR_WriteProcessMemory_4f3b {
  strings:
    $key_4f3b = { 18 49 [2] 2a 6b [2] 2c 5e [2] 02 5e [2] 3d 42 }

  condition:
    any of them
}