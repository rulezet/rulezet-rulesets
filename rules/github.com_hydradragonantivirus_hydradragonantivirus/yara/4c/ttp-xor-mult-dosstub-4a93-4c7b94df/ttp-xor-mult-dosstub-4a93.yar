rule TTP_XOR_MULT_DOSStub_4a93 {
  strings:
    $key_4a93 = { 1e fb [2] 6a e3 [2] 2d e1 [2] 6a f0 [2] 24 fc [2] 28 f6 [2] 3f fd [2] 24 b3 [2] 19 }

  condition:
    any of them
}