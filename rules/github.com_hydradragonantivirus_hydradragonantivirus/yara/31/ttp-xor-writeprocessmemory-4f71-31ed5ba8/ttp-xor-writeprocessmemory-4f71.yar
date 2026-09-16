rule TTP_XOR_WriteProcessMemory_4f71 {
  strings:
    $key_4f71 = { 18 03 [2] 2a 21 [2] 2c 14 [2] 02 14 [2] 3d 08 }

  condition:
    any of them
}