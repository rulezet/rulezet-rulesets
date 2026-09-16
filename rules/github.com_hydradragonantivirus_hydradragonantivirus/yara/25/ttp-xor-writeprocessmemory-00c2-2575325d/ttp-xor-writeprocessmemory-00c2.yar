rule TTP_XOR_WriteProcessMemory_00c2 {
  strings:
    $key_00c2 = { 57 b0 [2] 65 92 [2] 63 a7 [2] 4d a7 [2] 72 bb }

  condition:
    any of them
}