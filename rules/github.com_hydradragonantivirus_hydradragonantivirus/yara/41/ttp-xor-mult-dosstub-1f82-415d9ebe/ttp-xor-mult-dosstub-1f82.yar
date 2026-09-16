rule TTP_XOR_MULT_DOSStub_1f82 {
  strings:
    $key_1f82 = { 4b ea [2] 3f f2 [2] 78 f0 [2] 3f e1 [2] 71 ed [2] 7d e7 [2] 6a ec [2] 71 a2 [2] 4c }

  condition:
    any of them
}