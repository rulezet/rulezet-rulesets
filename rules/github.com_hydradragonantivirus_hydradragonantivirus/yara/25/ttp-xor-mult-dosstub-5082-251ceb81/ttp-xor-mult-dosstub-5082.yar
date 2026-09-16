rule TTP_XOR_MULT_DOSStub_5082 {
  strings:
    $key_5082 = { 04 ea [2] 70 f2 [2] 37 f0 [2] 70 e1 [2] 3e ed [2] 32 e7 [2] 25 ec [2] 3e a2 [2] 03 }

  condition:
    any of them
}