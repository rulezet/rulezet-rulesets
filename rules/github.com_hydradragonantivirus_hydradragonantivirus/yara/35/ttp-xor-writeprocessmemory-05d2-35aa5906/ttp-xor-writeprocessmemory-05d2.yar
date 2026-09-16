rule TTP_XOR_WriteProcessMemory_05d2 {
  strings:
    $key_05d2 = { 52 a0 [2] 60 82 [2] 66 b7 [2] 48 b7 [2] 77 ab }

  condition:
    any of them
}