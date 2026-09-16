rule TTP_XOR_WriteProcessMemory_5f71 {
  strings:
    $key_5f71 = { 08 03 [2] 3a 21 [2] 3c 14 [2] 12 14 [2] 2d 08 }

  condition:
    any of them
}