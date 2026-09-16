rule TTP_XOR_MULT_DOSStub_3f92 {
  strings:
    $key_3f92 = { 6b fa [2] 1f e2 [2] 58 e0 [2] 1f f1 [2] 51 fd [2] 5d f7 [2] 4a fc [2] 51 b2 [2] 6c }

  condition:
    any of them
}