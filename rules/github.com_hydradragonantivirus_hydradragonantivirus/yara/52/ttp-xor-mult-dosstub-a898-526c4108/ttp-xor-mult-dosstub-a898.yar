rule TTP_XOR_MULT_DOSStub_a898 {
  strings:
    $key_a898 = { fc f0 [2] 88 e8 [2] cf ea [2] 88 fb [2] c6 f7 [2] ca fd [2] dd f6 [2] c6 b8 [2] fb }

  condition:
    any of them
}