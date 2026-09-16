rule TTP_XOR_WriteProcessMemory_40d1 {
  strings:
    $key_40d1 = { 17 a3 [2] 25 81 [2] 23 b4 [2] 0d b4 [2] 32 a8 }

  condition:
    any of them
}