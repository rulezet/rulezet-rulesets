rule TTP_XOR_MULT_DOSStub_fbd3 {
  strings:
    $key_fbd3 = { af bb [2] db a3 [2] 9c a1 [2] db b0 [2] 95 bc [2] 99 b6 [2] 8e bd [2] 95 f3 [2] a8 }

  condition:
    any of them
}