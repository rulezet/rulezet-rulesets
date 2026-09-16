rule TTP_XOR_WriteProcessMemory_70e2 {
  strings:
    $key_70e2 = { 27 90 [2] 15 b2 [2] 13 87 [2] 3d 87 [2] 02 9b }

  condition:
    any of them
}