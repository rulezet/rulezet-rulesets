rule TTP_XOR_MULT_DOSStub_8a82 {
  strings:
    $key_8a82 = { de ea [2] aa f2 [2] ed f0 [2] aa e1 [2] e4 ed [2] e8 e7 [2] ff ec [2] e4 a2 [2] d9 }

  condition:
    any of them
}