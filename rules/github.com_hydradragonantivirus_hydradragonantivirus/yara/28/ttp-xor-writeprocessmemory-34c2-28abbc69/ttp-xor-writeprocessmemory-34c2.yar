rule TTP_XOR_WriteProcessMemory_34c2 {
  strings:
    $key_34c2 = { 63 b0 [2] 51 92 [2] 57 a7 [2] 79 a7 [2] 46 bb }

  condition:
    any of them
}