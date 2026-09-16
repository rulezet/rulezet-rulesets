rule TTP_XOR_MULT_DOSStub_ee84 {
  strings:
    $key_ee84 = { ba ec [2] ce f4 [2] 89 f6 [2] ce e7 [2] 80 eb [2] 8c e1 [2] 9b ea [2] 80 a4 [2] bd }

  condition:
    any of them
}