rule TTP_XOR_MULT_DOSStub_6f92 {
  strings:
    $key_6f92 = { 3b fa [2] 4f e2 [2] 08 e0 [2] 4f f1 [2] 01 fd [2] 0d f7 [2] 1a fc [2] 01 b2 [2] 3c }

  condition:
    any of them
}