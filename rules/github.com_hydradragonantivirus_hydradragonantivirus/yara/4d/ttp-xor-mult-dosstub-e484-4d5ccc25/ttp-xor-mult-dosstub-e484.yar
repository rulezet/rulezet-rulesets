rule TTP_XOR_MULT_DOSStub_e484 {
  strings:
    $key_e484 = { b0 ec [2] c4 f4 [2] 83 f6 [2] c4 e7 [2] 8a eb [2] 86 e1 [2] 91 ea [2] 8a a4 [2] b7 }

  condition:
    any of them
}