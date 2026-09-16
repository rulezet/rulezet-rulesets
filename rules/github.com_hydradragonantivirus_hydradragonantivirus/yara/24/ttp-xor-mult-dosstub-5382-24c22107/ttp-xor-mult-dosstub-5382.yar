rule TTP_XOR_MULT_DOSStub_5382 {
  strings:
    $key_5382 = { 07 ea [2] 73 f2 [2] 34 f0 [2] 73 e1 [2] 3d ed [2] 31 e7 [2] 26 ec [2] 3d a2 [2] 00 }

  condition:
    any of them
}