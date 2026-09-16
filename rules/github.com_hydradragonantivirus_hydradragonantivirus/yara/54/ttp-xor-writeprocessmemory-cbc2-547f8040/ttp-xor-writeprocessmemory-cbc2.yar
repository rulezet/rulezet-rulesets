rule TTP_XOR_WriteProcessMemory_cbc2 {
  strings:
    $key_cbc2 = { 9c b0 [2] ae 92 [2] a8 a7 [2] 86 a7 [2] b9 bb }

  condition:
    any of them
}