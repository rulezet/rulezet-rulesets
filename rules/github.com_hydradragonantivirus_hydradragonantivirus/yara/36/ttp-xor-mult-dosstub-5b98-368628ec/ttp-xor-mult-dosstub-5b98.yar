rule TTP_XOR_MULT_DOSStub_5b98 {
  strings:
    $key_5b98 = { 0f f0 [2] 7b e8 [2] 3c ea [2] 7b fb [2] 35 f7 [2] 39 fd [2] 2e f6 [2] 35 b8 [2] 08 }

  condition:
    any of them
}