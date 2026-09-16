rule TTP_XOR_WriteProcessMemory_06d4 {
  strings:
    $key_06d4 = { 51 a6 [2] 63 84 [2] 65 b1 [2] 4b b1 [2] 74 ad }

  condition:
    any of them
}