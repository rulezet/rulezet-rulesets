rule TTP_XOR_WriteProcessMemory_4ff0 {
  strings:
    $key_4ff0 = { 18 82 [2] 2a a0 [2] 2c 95 [2] 02 95 [2] 3d 89 }

  condition:
    any of them
}