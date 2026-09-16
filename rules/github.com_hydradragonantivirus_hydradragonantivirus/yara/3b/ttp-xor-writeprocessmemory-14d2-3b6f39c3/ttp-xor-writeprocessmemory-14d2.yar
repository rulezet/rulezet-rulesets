rule TTP_XOR_WriteProcessMemory_14d2 {
  strings:
    $key_14d2 = { 43 a0 [2] 71 82 [2] 77 b7 [2] 59 b7 [2] 66 ab }

  condition:
    any of them
}