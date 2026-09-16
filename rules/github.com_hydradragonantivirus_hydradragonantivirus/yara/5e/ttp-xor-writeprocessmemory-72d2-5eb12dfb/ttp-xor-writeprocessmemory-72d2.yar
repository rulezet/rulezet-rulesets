rule TTP_XOR_WriteProcessMemory_72d2 {
  strings:
    $key_72d2 = { 25 a0 [2] 17 82 [2] 11 b7 [2] 3f b7 [2] 00 ab }

  condition:
    any of them
}