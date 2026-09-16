rule TTP_XOR_MULT_DOSStub_0782 {
  strings:
    $key_0782 = { 53 ea [2] 27 f2 [2] 60 f0 [2] 27 e1 [2] 69 ed [2] 65 e7 [2] 72 ec [2] 69 a2 [2] 54 }

  condition:
    any of them
}