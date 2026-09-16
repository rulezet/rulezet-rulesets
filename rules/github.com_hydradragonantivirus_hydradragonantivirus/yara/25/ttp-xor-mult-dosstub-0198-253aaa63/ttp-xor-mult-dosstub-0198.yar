rule TTP_XOR_MULT_DOSStub_0198 {
  strings:
    $key_0198 = { 55 f0 [2] 21 e8 [2] 66 ea [2] 21 fb [2] 6f f7 [2] 63 fd [2] 74 f6 [2] 6f b8 [2] 52 }

  condition:
    any of them
}