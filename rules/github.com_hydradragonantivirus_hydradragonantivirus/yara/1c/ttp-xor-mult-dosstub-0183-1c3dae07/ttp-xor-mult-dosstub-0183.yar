rule TTP_XOR_MULT_DOSStub_0183 {
  strings:
    $key_0183 = { 55 eb [2] 21 f3 [2] 66 f1 [2] 21 e0 [2] 6f ec [2] 63 e6 [2] 74 ed [2] 6f a3 [2] 52 }

  condition:
    any of them
}