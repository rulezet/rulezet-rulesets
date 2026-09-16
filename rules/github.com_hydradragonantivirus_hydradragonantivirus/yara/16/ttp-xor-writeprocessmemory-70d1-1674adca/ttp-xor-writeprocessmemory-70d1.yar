rule TTP_XOR_WriteProcessMemory_70d1 {
  strings:
    $key_70d1 = { 27 a3 [2] 15 81 [2] 13 b4 [2] 3d b4 [2] 02 a8 }

  condition:
    any of them
}