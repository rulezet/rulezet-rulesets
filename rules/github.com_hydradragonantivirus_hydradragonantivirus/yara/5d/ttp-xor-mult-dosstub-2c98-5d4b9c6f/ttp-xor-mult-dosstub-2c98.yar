rule TTP_XOR_MULT_DOSStub_2c98 {
  strings:
    $key_2c98 = { 78 f0 [2] 0c e8 [2] 4b ea [2] 0c fb [2] 42 f7 [2] 4e fd [2] 59 f6 [2] 42 b8 [2] 7f }

  condition:
    any of them
}