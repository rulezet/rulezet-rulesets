rule TTP_XOR_MULT_DOSStub_0491 {
  strings:
    $key_0491 = { 50 f9 [2] 24 e1 [2] 63 e3 [2] 24 f2 [2] 6a fe [2] 66 f4 [2] 71 ff [2] 6a b1 [2] 57 }

  condition:
    any of them
}