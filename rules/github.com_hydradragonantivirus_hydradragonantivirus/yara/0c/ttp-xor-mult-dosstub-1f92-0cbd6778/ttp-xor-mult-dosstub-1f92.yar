rule TTP_XOR_MULT_DOSStub_1f92 {
  strings:
    $key_1f92 = { 4b fa [2] 3f e2 [2] 78 e0 [2] 3f f1 [2] 71 fd [2] 7d f7 [2] 6a fc [2] 71 b2 [2] 4c }

  condition:
    any of them
}