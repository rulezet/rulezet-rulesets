rule TTP_XOR_WriteProcessMemory_f3d2 {
  strings:
    $key_f3d2 = { a4 a0 [2] 96 82 [2] 90 b7 [2] be b7 [2] 81 ab }

  condition:
    any of them
}