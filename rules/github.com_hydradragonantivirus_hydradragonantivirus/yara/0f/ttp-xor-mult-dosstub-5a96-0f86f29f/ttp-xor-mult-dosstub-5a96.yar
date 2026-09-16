rule TTP_XOR_MULT_DOSStub_5a96 {
  strings:
    $key_5a96 = { 0e fe [2] 7a e6 [2] 3d e4 [2] 7a f5 [2] 34 f9 [2] 38 f3 [2] 2f f8 [2] 34 b6 [2] 09 }

  condition:
    any of them
}