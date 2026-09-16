rule TTP_XOR_WriteProcessMemory_3bc2 {
  strings:
    $key_3bc2 = { 6c b0 [2] 5e 92 [2] 58 a7 [2] 76 a7 [2] 49 bb }

  condition:
    any of them
}