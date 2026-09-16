rule TTP_XOR_WriteProcessMemory_23d2 {
  strings:
    $key_23d2 = { 74 a0 [2] 46 82 [2] 40 b7 [2] 6e b7 [2] 51 ab }

  condition:
    any of them
}