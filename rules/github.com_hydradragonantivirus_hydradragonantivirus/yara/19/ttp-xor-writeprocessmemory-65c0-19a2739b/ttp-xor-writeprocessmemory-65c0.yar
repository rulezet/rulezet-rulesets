rule TTP_XOR_WriteProcessMemory_65c0 {
  strings:
    $key_65c0 = { 32 b2 [2] 00 90 [2] 06 a5 [2] 28 a5 [2] 17 b9 }

  condition:
    any of them
}