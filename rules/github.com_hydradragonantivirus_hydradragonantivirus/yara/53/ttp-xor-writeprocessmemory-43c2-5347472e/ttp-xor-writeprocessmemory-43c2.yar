rule TTP_XOR_WriteProcessMemory_43c2 {
  strings:
    $key_43c2 = { 14 b0 [2] 26 92 [2] 20 a7 [2] 0e a7 [2] 31 bb }

  condition:
    any of them
}