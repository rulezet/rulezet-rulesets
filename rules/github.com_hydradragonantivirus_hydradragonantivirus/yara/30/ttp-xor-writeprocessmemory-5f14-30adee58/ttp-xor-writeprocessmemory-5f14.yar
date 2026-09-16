rule TTP_XOR_WriteProcessMemory_5f14 {
  strings:
    $key_5f14 = { 08 66 [2] 3a 44 [2] 3c 71 [2] 12 71 [2] 2d 6d }

  condition:
    any of them
}