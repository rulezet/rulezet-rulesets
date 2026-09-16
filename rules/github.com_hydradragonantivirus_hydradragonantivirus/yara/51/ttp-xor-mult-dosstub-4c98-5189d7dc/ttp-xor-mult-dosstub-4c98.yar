rule TTP_XOR_MULT_DOSStub_4c98 {
  strings:
    $key_4c98 = { 18 f0 [2] 6c e8 [2] 2b ea [2] 6c fb [2] 22 f7 [2] 2e fd [2] 39 f6 [2] 22 b8 [2] 1f }

  condition:
    any of them
}