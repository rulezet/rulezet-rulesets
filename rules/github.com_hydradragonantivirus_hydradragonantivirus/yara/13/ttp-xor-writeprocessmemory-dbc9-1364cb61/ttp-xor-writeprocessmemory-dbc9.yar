rule TTP_XOR_WriteProcessMemory_dbc9 {
  strings:
    $key_dbc9 = { 8c bb [2] be 99 [2] b8 ac [2] 96 ac [2] a9 b0 }

  condition:
    any of them
}