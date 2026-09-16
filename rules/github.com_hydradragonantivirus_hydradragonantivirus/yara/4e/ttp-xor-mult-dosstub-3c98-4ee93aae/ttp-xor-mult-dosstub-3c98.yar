rule TTP_XOR_MULT_DOSStub_3c98 {
  strings:
    $key_3c98 = { 68 f0 [2] 1c e8 [2] 5b ea [2] 1c fb [2] 52 f7 [2] 5e fd [2] 49 f6 [2] 52 b8 [2] 6f }

  condition:
    any of them
}