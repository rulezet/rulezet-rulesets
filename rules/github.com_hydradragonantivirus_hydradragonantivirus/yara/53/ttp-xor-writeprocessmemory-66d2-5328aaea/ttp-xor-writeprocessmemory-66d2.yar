rule TTP_XOR_WriteProcessMemory_66d2 {
  strings:
    $key_66d2 = { 31 a0 [2] 03 82 [2] 05 b7 [2] 2b b7 [2] 14 ab }

  condition:
    any of them
}