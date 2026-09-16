rule TTP_XOR_MULT_DOSStub_c183 {
  strings:
    $key_c183 = { 95 eb [2] e1 f3 [2] a6 f1 [2] e1 e0 [2] af ec [2] a3 e6 [2] b4 ed [2] af a3 [2] 92 }

  condition:
    any of them
}