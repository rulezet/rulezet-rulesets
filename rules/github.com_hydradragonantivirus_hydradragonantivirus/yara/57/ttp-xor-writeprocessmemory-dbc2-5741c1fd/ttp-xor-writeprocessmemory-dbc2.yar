rule TTP_XOR_WriteProcessMemory_dbc2 {
  strings:
    $key_dbc2 = { 8c b0 [2] be 92 [2] b8 a7 [2] 96 a7 [2] a9 bb }

  condition:
    any of them
}