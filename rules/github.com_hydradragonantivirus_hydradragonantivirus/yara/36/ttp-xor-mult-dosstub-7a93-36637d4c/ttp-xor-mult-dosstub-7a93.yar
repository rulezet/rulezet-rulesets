rule TTP_XOR_MULT_DOSStub_7a93 {
  strings:
    $key_7a93 = { 2e fb [2] 5a e3 [2] 1d e1 [2] 5a f0 [2] 14 fc [2] 18 f6 [2] 0f fd [2] 14 b3 [2] 29 }

  condition:
    any of them
}