rule TTP_XOR_MULT_DOSStub_2598 {
  strings:
    $key_2598 = { 71 f0 [2] 05 e8 [2] 42 ea [2] 05 fb [2] 4b f7 [2] 47 fd [2] 50 f6 [2] 4b b8 [2] 76 }

  condition:
    any of them
}