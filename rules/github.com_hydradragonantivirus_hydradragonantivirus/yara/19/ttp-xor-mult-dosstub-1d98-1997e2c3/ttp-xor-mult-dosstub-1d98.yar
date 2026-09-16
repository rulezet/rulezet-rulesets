rule TTP_XOR_MULT_DOSStub_1d98 {
  strings:
    $key_1d98 = { 49 f0 [2] 3d e8 [2] 7a ea [2] 3d fb [2] 73 f7 [2] 7f fd [2] 68 f6 [2] 73 b8 [2] 4e }

  condition:
    any of them
}