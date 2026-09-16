rule TTP_XOR_WriteProcessMemory_e8d1 {
  strings:
    $key_e8d1 = { bf a3 [2] 8d 81 [2] 8b b4 [2] a5 b4 [2] 9a a8 }

  condition:
    any of them
}