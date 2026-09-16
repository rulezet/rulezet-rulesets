rule TTP_XOR_WriteProcessMemory_e7d1 {
  strings:
    $key_e7d1 = { b0 a3 [2] 82 81 [2] 84 b4 [2] aa b4 [2] 95 a8 }

  condition:
    any of them
}