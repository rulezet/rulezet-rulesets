rule TTP_XOR_WriteProcessMemory_5856 {
  strings:
    $key_5856 = { 0f 24 [2] 3d 06 [2] 3b 33 [2] 15 33 [2] 2a 2f }

  condition:
    any of them
}