rule TTP_XOR_MULT_DOSStub_e8c0 {
  strings:
    $key_e8c0 = { bc a8 [2] c8 b0 [2] 8f b2 [2] c8 a3 [2] 86 af [2] 8a a5 [2] 9d ae [2] 86 e0 [2] bb }

  condition:
    any of them
}