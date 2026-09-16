rule TTP_XOR_WriteProcessMemory_5ac2 {
  strings:
    $key_5ac2 = { 0d b0 [2] 3f 92 [2] 39 a7 [2] 17 a7 [2] 28 bb }

  condition:
    any of them
}