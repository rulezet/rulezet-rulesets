rule TTP_XOR_WriteProcessMemory_34d2 {
  strings:
    $key_34d2 = { 63 a0 [2] 51 82 [2] 57 b7 [2] 79 b7 [2] 46 ab }

  condition:
    any of them
}