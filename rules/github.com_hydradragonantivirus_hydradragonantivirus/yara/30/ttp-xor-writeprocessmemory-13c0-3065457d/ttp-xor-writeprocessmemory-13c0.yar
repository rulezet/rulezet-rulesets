rule TTP_XOR_WriteProcessMemory_13c0 {
  strings:
    $key_13c0 = { 44 b2 [2] 76 90 [2] 70 a5 [2] 5e a5 [2] 61 b9 }

  condition:
    any of them
}