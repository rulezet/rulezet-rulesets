rule TTP_XOR_MULT_DOSStub_eac0 {
  strings:
    $key_eac0 = { be a8 [2] ca b0 [2] 8d b2 [2] ca a3 [2] 84 af [2] 88 a5 [2] 9f ae [2] 84 e0 [2] b9 }

  condition:
    any of them
}