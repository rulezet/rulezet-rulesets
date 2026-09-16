rule TTP_XOR_WriteProcessMemory_45c0 {
  strings:
    $key_45c0 = { 12 b2 [2] 20 90 [2] 26 a5 [2] 08 a5 [2] 37 b9 }

  condition:
    any of them
}