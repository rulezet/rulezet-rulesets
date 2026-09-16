rule TTP_XOR_MULT_DOSStub_ead2 {
  strings:
    $key_ead2 = { be ba [2] ca a2 [2] 8d a0 [2] ca b1 [2] 84 bd [2] 88 b7 [2] 9f bc [2] 84 f2 [2] b9 }

  condition:
    any of them
}