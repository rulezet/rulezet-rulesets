rule TTP_XOR_WriteProcessMemory_06d1 {
  strings:
    $key_06d1 = { 51 a3 [2] 63 81 [2] 65 b4 [2] 4b b4 [2] 74 a8 }

  condition:
    any of them
}