rule TTP_XOR_MULT_DOSStub_3082 {
  strings:
    $key_3082 = { 64 ea [2] 10 f2 [2] 57 f0 [2] 10 e1 [2] 5e ed [2] 52 e7 [2] 45 ec [2] 5e a2 [2] 63 }

  condition:
    any of them
}