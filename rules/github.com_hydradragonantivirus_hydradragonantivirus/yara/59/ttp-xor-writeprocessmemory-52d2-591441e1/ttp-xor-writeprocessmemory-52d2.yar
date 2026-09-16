rule TTP_XOR_WriteProcessMemory_52d2 {
  strings:
    $key_52d2 = { 05 a0 [2] 37 82 [2] 31 b7 [2] 1f b7 [2] 20 ab }

  condition:
    any of them
}