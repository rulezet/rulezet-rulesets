rule TTP_XOR_MULT_DOSStub_1782 {
  strings:
    $key_1782 = { 43 ea [2] 37 f2 [2] 70 f0 [2] 37 e1 [2] 79 ed [2] 75 e7 [2] 62 ec [2] 79 a2 [2] 44 }

  condition:
    any of them
}