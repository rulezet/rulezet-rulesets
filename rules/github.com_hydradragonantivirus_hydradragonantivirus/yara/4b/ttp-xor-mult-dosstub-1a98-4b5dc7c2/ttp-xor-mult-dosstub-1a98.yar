rule TTP_XOR_MULT_DOSStub_1a98 {
  strings:
    $key_1a98 = { 4e f0 [2] 3a e8 [2] 7d ea [2] 3a fb [2] 74 f7 [2] 78 fd [2] 6f f6 [2] 74 b8 [2] 49 }

  condition:
    any of them
}