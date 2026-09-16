rule TTP_XOR_WriteProcessMemory_dcc6 {
  strings:
    $key_dcc6 = { 8b b4 [2] b9 96 [2] bf a3 [2] 91 a3 [2] ae bf }

  condition:
    any of them
}