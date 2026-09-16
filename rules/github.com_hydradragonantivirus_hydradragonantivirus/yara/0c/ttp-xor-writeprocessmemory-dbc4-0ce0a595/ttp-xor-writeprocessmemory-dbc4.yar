rule TTP_XOR_WriteProcessMemory_dbc4 {
  strings:
    $key_dbc4 = { 8c b6 [2] be 94 [2] b8 a1 [2] 96 a1 [2] a9 bd }

  condition:
    any of them
}