rule TTP_XOR_WriteProcessMemory_7066 {
  strings:
    $key_7066 = { 27 14 [2] 15 36 [2] 13 03 [2] 3d 03 [2] 02 1f }

  condition:
    any of them
}