rule TTP_XOR_MULT_DOSStub_1082 {
  strings:
    $key_1082 = { 44 ea [2] 30 f2 [2] 77 f0 [2] 30 e1 [2] 7e ed [2] 72 e7 [2] 65 ec [2] 7e a2 [2] 43 }

  condition:
    any of them
}