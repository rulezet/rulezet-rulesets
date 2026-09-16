rule TTP_XOR_WriteProcessMemory_6a26 {
  strings:
    $key_6a26 = { 3d 54 [2] 0f 76 [2] 09 43 [2] 27 43 [2] 18 5f }

  condition:
    any of them
}