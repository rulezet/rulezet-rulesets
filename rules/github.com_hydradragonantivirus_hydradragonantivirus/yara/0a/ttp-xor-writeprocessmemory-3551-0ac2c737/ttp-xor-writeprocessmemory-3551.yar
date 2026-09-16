rule TTP_XOR_WriteProcessMemory_3551 {
  strings:
    $key_3551 = { 62 23 [2] 50 01 [2] 56 34 [2] 78 34 [2] 47 28 }

  condition:
    any of them
}