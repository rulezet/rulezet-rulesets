rule TTP_XOR_WriteProcessMemory_6bc2 {
  strings:
    $key_6bc2 = { 3c b0 [2] 0e 92 [2] 08 a7 [2] 26 a7 [2] 19 bb }

  condition:
    any of them
}