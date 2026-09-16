rule TTP_XOR_WriteProcessMemory_5ee4 {
  strings:
    $key_5ee4 = { 09 96 [2] 3b b4 [2] 3d 81 [2] 13 81 [2] 2c 9d }

  condition:
    any of them
}