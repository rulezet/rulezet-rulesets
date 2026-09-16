rule TTP_XOR_MULT_DOSStub_3598 {
  strings:
    $key_3598 = { 61 f0 [2] 15 e8 [2] 52 ea [2] 15 fb [2] 5b f7 [2] 57 fd [2] 40 f6 [2] 5b b8 [2] 66 }

  condition:
    any of them
}