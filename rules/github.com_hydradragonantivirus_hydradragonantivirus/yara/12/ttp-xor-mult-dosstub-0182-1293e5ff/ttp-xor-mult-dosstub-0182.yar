rule TTP_XOR_MULT_DOSStub_0182 {
  strings:
    $key_0182 = { 55 ea [2] 21 f2 [2] 66 f0 [2] 21 e1 [2] 6f ed [2] 63 e7 [2] 74 ec [2] 6f a2 [2] 52 }

  condition:
    any of them
}