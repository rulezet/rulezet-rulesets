rule TTP_XOR_MULT_DOSStub_4d92 {
  strings:
    $key_4d92 = { 19 fa [2] 6d e2 [2] 2a e0 [2] 6d f1 [2] 23 fd [2] 2f f7 [2] 38 fc [2] 23 b2 [2] 1e }

  condition:
    any of them
}