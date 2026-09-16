rule TTP_XOR_MULT_DOSStub_3d95 {
  strings:
    $key_3d95 = { 69 fd [2] 1d e5 [2] 5a e7 [2] 1d f6 [2] 53 fa [2] 5f f0 [2] 48 fb [2] 53 b5 [2] 6e }

  condition:
    any of them
}