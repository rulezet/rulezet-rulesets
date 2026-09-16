rule TTP_XOR_WriteProcessMemory_14d1 {
  strings:
    $key_14d1 = { 43 a3 [2] 71 81 [2] 77 b4 [2] 59 b4 [2] 66 a8 }

  condition:
    any of them
}