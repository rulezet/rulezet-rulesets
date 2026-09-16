rule TTP_XOR_MULT_DOSStub_0d95 {
  strings:
    $key_0d95 = { 59 fd [2] 2d e5 [2] 6a e7 [2] 2d f6 [2] 63 fa [2] 6f f0 [2] 78 fb [2] 63 b5 [2] 5e }

  condition:
    any of them
}