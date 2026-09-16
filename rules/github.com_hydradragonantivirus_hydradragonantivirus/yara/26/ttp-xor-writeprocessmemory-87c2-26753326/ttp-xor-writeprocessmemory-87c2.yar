rule TTP_XOR_WriteProcessMemory_87c2 {
  strings:
    $key_87c2 = { d0 b0 [2] e2 92 [2] e4 a7 [2] ca a7 [2] f5 bb }

  condition:
    any of them
}