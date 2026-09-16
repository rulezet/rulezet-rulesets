rule TTP_XOR_WriteProcessMemory_6a56 {
  strings:
    $key_6a56 = { 3d 24 [2] 0f 06 [2] 09 33 [2] 27 33 [2] 18 2f }

  condition:
    any of them
}