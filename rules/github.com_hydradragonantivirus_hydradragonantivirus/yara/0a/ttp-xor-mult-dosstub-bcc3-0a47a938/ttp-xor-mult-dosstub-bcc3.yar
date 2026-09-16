rule TTP_XOR_MULT_DOSStub_bcc3 {
  strings:
    $key_bcc3 = { e8 ab [2] 9c b3 [2] db b1 [2] 9c a0 [2] d2 ac [2] de a6 [2] c9 ad [2] d2 e3 [2] ef }

  condition:
    any of them
}