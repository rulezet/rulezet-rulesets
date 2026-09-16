rule TTP_XOR_WriteProcessMemory_1bd2 {
  strings:
    $key_1bd2 = { 4c a0 [2] 7e 82 [2] 78 b7 [2] 56 b7 [2] 69 ab }

  condition:
    any of them
}