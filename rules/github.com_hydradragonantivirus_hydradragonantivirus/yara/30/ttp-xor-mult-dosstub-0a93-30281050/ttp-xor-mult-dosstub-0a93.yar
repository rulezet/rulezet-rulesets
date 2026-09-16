rule TTP_XOR_MULT_DOSStub_0a93 {
  strings:
    $key_0a93 = { 5e fb [2] 2a e3 [2] 6d e1 [2] 2a f0 [2] 64 fc [2] 68 f6 [2] 7f fd [2] 64 b3 [2] 59 }

  condition:
    any of them
}