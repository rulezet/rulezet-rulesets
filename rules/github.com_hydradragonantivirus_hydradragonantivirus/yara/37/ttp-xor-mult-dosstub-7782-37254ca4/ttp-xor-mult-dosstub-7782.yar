rule TTP_XOR_MULT_DOSStub_7782 {
  strings:
    $key_7782 = { 23 ea [2] 57 f2 [2] 10 f0 [2] 57 e1 [2] 19 ed [2] 15 e7 [2] 02 ec [2] 19 a2 [2] 24 }

  condition:
    any of them
}