rule TTP_XOR_WriteProcessMemory_dbc6 {
  strings:
    $key_dbc6 = { 8c b4 [2] be 96 [2] b8 a3 [2] 96 a3 [2] a9 bf }

  condition:
    any of them
}