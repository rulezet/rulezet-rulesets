rule TTP_XOR_WriteProcessMemory_2bc2 {
  strings:
    $key_2bc2 = { 7c b0 [2] 4e 92 [2] 48 a7 [2] 66 a7 [2] 59 bb }

  condition:
    any of them
}