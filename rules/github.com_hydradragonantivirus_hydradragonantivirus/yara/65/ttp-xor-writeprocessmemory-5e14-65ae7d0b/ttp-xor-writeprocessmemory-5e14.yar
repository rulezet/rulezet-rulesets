rule TTP_XOR_WriteProcessMemory_5e14 {
  strings:
    $key_5e14 = { 09 66 [2] 3b 44 [2] 3d 71 [2] 13 71 [2] 2c 6d }

  condition:
    any of them
}