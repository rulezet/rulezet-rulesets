rule TTP_XOR_WriteProcessMemory_25d2 {
  strings:
    $key_25d2 = { 72 a0 [2] 40 82 [2] 46 b7 [2] 68 b7 [2] 57 ab }

  condition:
    any of them
}