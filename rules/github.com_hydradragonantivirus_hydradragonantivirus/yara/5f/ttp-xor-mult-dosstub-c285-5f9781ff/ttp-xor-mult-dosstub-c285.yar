rule TTP_XOR_MULT_DOSStub_c285 {
  strings:
    $key_c285 = { 96 ed [2] e2 f5 [2] a5 f7 [2] e2 e6 [2] ac ea [2] a0 e0 [2] b7 eb [2] ac a5 [2] 91 }

  condition:
    any of them
}