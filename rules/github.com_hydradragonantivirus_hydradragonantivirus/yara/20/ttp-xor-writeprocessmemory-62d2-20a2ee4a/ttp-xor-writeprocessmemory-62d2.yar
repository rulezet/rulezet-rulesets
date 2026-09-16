rule TTP_XOR_WriteProcessMemory_62d2 {
  strings:
    $key_62d2 = { 35 a0 [2] 07 82 [2] 01 b7 [2] 2f b7 [2] 10 ab }

  condition:
    any of them
}