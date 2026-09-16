rule TTP_XOR_MULT_DOSStub_7284 {
  strings:
    $key_7284 = { 26 ec [2] 52 f4 [2] 15 f6 [2] 52 e7 [2] 1c eb [2] 10 e1 [2] 07 ea [2] 1c a4 [2] 21 }

  condition:
    any of them
}