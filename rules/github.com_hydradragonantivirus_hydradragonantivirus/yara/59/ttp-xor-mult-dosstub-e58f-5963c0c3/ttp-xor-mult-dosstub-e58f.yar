rule TTP_XOR_MULT_DOSStub_e58f {
  strings:
    $key_e58f = { b1 e7 [2] c5 ff [2] 82 fd [2] c5 ec [2] 8b e0 [2] 87 ea [2] 90 e1 [2] 8b af [2] b6 }

  condition:
    any of them
}