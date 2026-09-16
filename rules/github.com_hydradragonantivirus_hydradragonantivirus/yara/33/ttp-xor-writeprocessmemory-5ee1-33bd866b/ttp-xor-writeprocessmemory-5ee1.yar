rule TTP_XOR_WriteProcessMemory_5ee1 {
  strings:
    $key_5ee1 = { 09 93 [2] 3b b1 [2] 3d 84 [2] 13 84 [2] 2c 98 }

  condition:
    any of them
}