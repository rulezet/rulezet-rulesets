rule TTP_XOR_WriteProcessMemory_72c2 {
  strings:
    $key_72c2 = { 25 b0 [2] 17 92 [2] 11 a7 [2] 3f a7 [2] 00 bb }

  condition:
    any of them
}