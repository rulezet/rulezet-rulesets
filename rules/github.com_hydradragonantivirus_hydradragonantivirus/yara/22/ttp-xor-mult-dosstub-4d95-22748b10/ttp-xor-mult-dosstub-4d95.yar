rule TTP_XOR_MULT_DOSStub_4d95 {
  strings:
    $key_4d95 = { 19 fd [2] 6d e5 [2] 2a e7 [2] 6d f6 [2] 23 fa [2] 2f f0 [2] 38 fb [2] 23 b5 [2] 1e }

  condition:
    any of them
}