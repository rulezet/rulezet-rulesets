rule TTP_XOR_MULT_DOSStub_2b98 {
  strings:
    $key_2b98 = { 7f f0 [2] 0b e8 [2] 4c ea [2] 0b fb [2] 45 f7 [2] 49 fd [2] 5e f6 [2] 45 b8 [2] 78 }

  condition:
    any of them
}