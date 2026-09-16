rule TTP_XOR_MULT_DOSStub_1382 {
  strings:
    $key_1382 = { 47 ea [2] 33 f2 [2] 74 f0 [2] 33 e1 [2] 7d ed [2] 71 e7 [2] 66 ec [2] 7d a2 [2] 40 }

  condition:
    any of them
}