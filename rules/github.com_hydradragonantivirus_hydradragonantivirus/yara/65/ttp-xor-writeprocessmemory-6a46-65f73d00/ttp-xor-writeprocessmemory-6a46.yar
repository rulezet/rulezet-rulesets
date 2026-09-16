rule TTP_XOR_WriteProcessMemory_6a46 {
  strings:
    $key_6a46 = { 3d 34 [2] 0f 16 [2] 09 23 [2] 27 23 [2] 18 3f }

  condition:
    any of them
}