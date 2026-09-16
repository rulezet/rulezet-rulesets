rule TTP_XOR_WriteProcessMemory_e0d2 {
  strings:
    $key_e0d2 = { b7 a0 [2] 85 82 [2] 83 b7 [2] ad b7 [2] 92 ab }

  condition:
    any of them
}