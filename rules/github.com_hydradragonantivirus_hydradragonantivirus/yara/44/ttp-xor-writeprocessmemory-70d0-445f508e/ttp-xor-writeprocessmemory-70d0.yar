rule TTP_XOR_WriteProcessMemory_70d0 {
  strings:
    $key_70d0 = { 27 a2 [2] 15 80 [2] 13 b5 [2] 3d b5 [2] 02 a9 }

  condition:
    any of them
}