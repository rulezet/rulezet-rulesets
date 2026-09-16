rule TTP_XOR_WriteProcessMemory_f3d1 {
  strings:
    $key_f3d1 = { a4 a3 [2] 96 81 [2] 90 b4 [2] be b4 [2] 81 a8 }

  condition:
    any of them
}