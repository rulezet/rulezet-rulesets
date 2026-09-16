rule TTP_XOR_MULT_DOSStub_5f92 {
  strings:
    $key_5f92 = { 0b fa [2] 7f e2 [2] 38 e0 [2] 7f f1 [2] 31 fd [2] 3d f7 [2] 2a fc [2] 31 b2 [2] 0c }

  condition:
    any of them
}