rule TTP_XOR_WriteProcessMemory_6bd2 {
  strings:
    $key_6bd2 = { 3c a0 [2] 0e 82 [2] 08 b7 [2] 26 b7 [2] 19 ab }

  condition:
    any of them
}