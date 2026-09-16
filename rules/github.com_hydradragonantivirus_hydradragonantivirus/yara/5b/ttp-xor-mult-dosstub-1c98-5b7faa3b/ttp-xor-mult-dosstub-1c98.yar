rule TTP_XOR_MULT_DOSStub_1c98 {
  strings:
    $key_1c98 = { 48 f0 [2] 3c e8 [2] 7b ea [2] 3c fb [2] 72 f7 [2] 7e fd [2] 69 f6 [2] 72 b8 [2] 4f }

  condition:
    any of them
}