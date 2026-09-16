rule TTP_XOR_MULT_DOSStub_fb98 {
  strings:
    $key_fb98 = { af f0 [2] db e8 [2] 9c ea [2] db fb [2] 95 f7 [2] 99 fd [2] 8e f6 [2] 95 b8 [2] a8 }

  condition:
    any of them
}