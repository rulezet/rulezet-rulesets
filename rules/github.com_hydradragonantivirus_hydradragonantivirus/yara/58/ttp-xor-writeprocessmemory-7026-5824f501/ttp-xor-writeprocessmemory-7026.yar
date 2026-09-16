rule TTP_XOR_WriteProcessMemory_7026 {
  strings:
    $key_7026 = { 27 54 [2] 15 76 [2] 13 43 [2] 3d 43 [2] 02 5f }

  condition:
    any of them
}