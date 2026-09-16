rule TTP_XOR_MULT_DOSStub_7f92 {
  strings:
    $key_7f92 = { 2b fa [2] 5f e2 [2] 18 e0 [2] 5f f1 [2] 11 fd [2] 1d f7 [2] 0a fc [2] 11 b2 [2] 2c }

  condition:
    any of them
}