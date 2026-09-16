rule TTP_XOR_WriteProcessMemory_10d1 {
  strings:
    $key_10d1 = { 47 a3 [2] 75 81 [2] 73 b4 [2] 5d b4 [2] 62 a8 }

  condition:
    any of them
}