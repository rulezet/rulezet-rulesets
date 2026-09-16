rule TTP_XOR_MULT_DOSStub_a2c5 {
  strings:
    $key_a2c5 = { f6 ad [2] 82 b5 [2] c5 b7 [2] 82 a6 [2] cc aa [2] c0 a0 [2] d7 ab [2] cc e5 [2] f1 }

  condition:
    any of them
}