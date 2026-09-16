rule TTP_XOR_WriteProcessMemory_5ee0 {
  strings:
    $key_5ee0 = { 09 92 [2] 3b b0 [2] 3d 85 [2] 13 85 [2] 2c 99 }

  condition:
    any of them
}