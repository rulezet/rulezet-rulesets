rule TTP_XOR_MULT_DOSStub_7182 {
  strings:
    $key_7182 = { 25 ea [2] 51 f2 [2] 16 f0 [2] 51 e1 [2] 1f ed [2] 13 e7 [2] 04 ec [2] 1f a2 [2] 22 }

  condition:
    any of them
}