rule TTP_XOR_WriteProcessMemory_5ed6 {
  strings:
    $key_5ed6 = { 09 a4 [2] 3b 86 [2] 3d b3 [2] 13 b3 [2] 2c af }

  condition:
    any of them
}