rule TTP_XOR_WriteProcessMemory_04c2 {
  strings:
    $key_04c2 = { 53 b0 [2] 61 92 [2] 67 a7 [2] 49 a7 [2] 76 bb }

  condition:
    any of them
}