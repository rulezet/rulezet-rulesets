rule TTP_XOR_WriteProcessMemory_5e20 {
  strings:
    $key_5e20 = { 09 52 [2] 3b 70 [2] 3d 45 [2] 13 45 [2] 2c 59 }

  condition:
    any of them
}