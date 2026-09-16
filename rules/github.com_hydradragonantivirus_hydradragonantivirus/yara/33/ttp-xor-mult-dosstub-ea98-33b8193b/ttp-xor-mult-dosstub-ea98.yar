rule TTP_XOR_MULT_DOSStub_ea98 {
  strings:
    $key_ea98 = { be f0 [2] ca e8 [2] 8d ea [2] ca fb [2] 84 f7 [2] 88 fd [2] 9f f6 [2] 84 b8 [2] b9 }

  condition:
    any of them
}