rule TTP_XOR_MULT_DOSStub_ea89 {
  strings:
    $key_ea89 = { be e1 [2] ca f9 [2] 8d fb [2] ca ea [2] 84 e6 [2] 88 ec [2] 9f e7 [2] 84 a9 [2] b9 }

  condition:
    any of them
}