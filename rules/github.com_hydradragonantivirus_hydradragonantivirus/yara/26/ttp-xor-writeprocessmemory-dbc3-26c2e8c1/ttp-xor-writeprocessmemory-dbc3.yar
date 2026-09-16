rule TTP_XOR_WriteProcessMemory_dbc3 {
  strings:
    $key_dbc3 = { 8c b1 [2] be 93 [2] b8 a6 [2] 96 a6 [2] a9 ba }

  condition:
    any of them
}