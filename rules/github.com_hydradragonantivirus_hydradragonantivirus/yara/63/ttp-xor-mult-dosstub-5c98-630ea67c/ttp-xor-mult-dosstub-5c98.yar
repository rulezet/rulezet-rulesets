rule TTP_XOR_MULT_DOSStub_5c98 {
  strings:
    $key_5c98 = { 08 f0 [2] 7c e8 [2] 3b ea [2] 7c fb [2] 32 f7 [2] 3e fd [2] 29 f6 [2] 32 b8 [2] 0f }

  condition:
    any of them
}