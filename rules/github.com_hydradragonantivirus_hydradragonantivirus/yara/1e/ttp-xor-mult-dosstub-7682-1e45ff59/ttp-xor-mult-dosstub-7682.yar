rule TTP_XOR_MULT_DOSStub_7682 {
  strings:
    $key_7682 = { 22 ea [2] 56 f2 [2] 11 f0 [2] 56 e1 [2] 18 ed [2] 14 e7 [2] 03 ec [2] 18 a2 [2] 25 }

  condition:
    any of them
}