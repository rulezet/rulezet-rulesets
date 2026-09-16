rule TTP_XOR_WriteProcessMemory_3fc2 {
  strings:
    $key_3fc2 = { 68 b0 [2] 5a 92 [2] 5c a7 [2] 72 a7 [2] 4d bb }

  condition:
    any of them
}