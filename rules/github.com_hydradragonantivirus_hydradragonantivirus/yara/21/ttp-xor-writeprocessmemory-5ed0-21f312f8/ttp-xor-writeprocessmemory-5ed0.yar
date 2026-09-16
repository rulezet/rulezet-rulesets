rule TTP_XOR_WriteProcessMemory_5ed0 {
  strings:
    $key_5ed0 = { 09 a2 [2] 3b 80 [2] 3d b5 [2] 13 b5 [2] 2c a9 }

  condition:
    any of them
}