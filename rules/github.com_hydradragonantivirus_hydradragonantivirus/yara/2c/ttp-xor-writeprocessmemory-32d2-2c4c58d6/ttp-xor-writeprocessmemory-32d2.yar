rule TTP_XOR_WriteProcessMemory_32d2 {
  strings:
    $key_32d2 = { 65 a0 [2] 57 82 [2] 51 b7 [2] 7f b7 [2] 40 ab }

  condition:
    any of them
}