rule TTP_XOR_MULT_DOSStub_0f82 {
  strings:
    $key_0f82 = { 5b ea [2] 2f f2 [2] 68 f0 [2] 2f e1 [2] 61 ed [2] 6d e7 [2] 7a ec [2] 61 a2 [2] 5c }

  condition:
    any of them
}