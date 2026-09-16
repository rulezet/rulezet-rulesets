rule TTP_XOR_MULT_DOSStub_eac6 {
  strings:
    $key_eac6 = { be ae [2] ca b6 [2] 8d b4 [2] ca a5 [2] 84 a9 [2] 88 a3 [2] 9f a8 [2] 84 e6 [2] b9 }

  condition:
    any of them
}