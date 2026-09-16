rule TTP_XOR_MULT_DOSStub_fa98 {
  strings:
    $key_fa98 = { ae f0 [2] da e8 [2] 9d ea [2] da fb [2] 94 f7 [2] 98 fd [2] 8f f6 [2] 94 b8 [2] a9 }

  condition:
    any of them
}