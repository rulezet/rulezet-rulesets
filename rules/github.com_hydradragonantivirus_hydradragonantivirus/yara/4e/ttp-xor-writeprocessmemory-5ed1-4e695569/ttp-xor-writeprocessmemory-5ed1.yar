rule TTP_XOR_WriteProcessMemory_5ed1 {
  strings:
    $key_5ed1 = { 09 a3 [2] 3b 81 [2] 3d b4 [2] 13 b4 [2] 2c a8 }

  condition:
    any of them
}