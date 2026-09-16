rule TTP_XOR_WriteProcessMemory_0ac2 {
  strings:
    $key_0ac2 = { 5d b0 [2] 6f 92 [2] 69 a7 [2] 47 a7 [2] 78 bb }

  condition:
    any of them
}