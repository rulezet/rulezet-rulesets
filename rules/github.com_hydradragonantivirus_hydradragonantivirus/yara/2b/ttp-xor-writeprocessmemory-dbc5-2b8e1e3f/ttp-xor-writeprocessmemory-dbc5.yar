rule TTP_XOR_WriteProcessMemory_dbc5 {
  strings:
    $key_dbc5 = { 8c b7 [2] be 95 [2] b8 a0 [2] 96 a0 [2] a9 bc }

  condition:
    any of them
}