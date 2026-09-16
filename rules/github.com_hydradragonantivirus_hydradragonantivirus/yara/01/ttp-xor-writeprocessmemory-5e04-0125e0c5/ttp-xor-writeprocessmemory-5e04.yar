rule TTP_XOR_WriteProcessMemory_5e04 {
  strings:
    $key_5e04 = { 09 76 [2] 3b 54 [2] 3d 61 [2] 13 61 [2] 2c 7d }

  condition:
    any of them
}