rule TTP_XOR_MULT_DOSStub_8782 {
  strings:
    $key_8782 = { d3 ea [2] a7 f2 [2] e0 f0 [2] a7 e1 [2] e9 ed [2] e5 e7 [2] f2 ec [2] e9 a2 [2] d4 }

  condition:
    any of them
}