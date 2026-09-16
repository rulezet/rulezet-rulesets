rule TTP_XOR_MULT_DOSStub_4d98 {
  strings:
    $key_4d98 = { 19 f0 [2] 6d e8 [2] 2a ea [2] 6d fb [2] 23 f7 [2] 2f fd [2] 38 f6 [2] 23 b8 [2] 1e }

  condition:
    any of them
}