rule TTP_XOR_MULT_DOSStub_3698 {
  strings:
    $key_3698 = { 62 f0 [2] 16 e8 [2] 51 ea [2] 16 fb [2] 58 f7 [2] 54 fd [2] 43 f6 [2] 58 b8 [2] 65 }

  condition:
    any of them
}