rule TTP_XOR_WriteProcessMemory_10d2 {
  strings:
    $key_10d2 = { 47 a0 [2] 75 82 [2] 73 b7 [2] 5d b7 [2] 62 ab }

  condition:
    any of them
}