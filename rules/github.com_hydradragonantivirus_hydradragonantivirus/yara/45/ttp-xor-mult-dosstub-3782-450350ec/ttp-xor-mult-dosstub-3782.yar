rule TTP_XOR_MULT_DOSStub_3782 {
  strings:
    $key_3782 = { 63 ea [2] 17 f2 [2] 50 f0 [2] 17 e1 [2] 59 ed [2] 55 e7 [2] 42 ec [2] 59 a2 [2] 64 }

  condition:
    any of them
}