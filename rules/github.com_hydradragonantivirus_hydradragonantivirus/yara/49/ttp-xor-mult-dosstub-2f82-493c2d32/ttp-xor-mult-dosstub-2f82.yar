rule TTP_XOR_MULT_DOSStub_2f82 {
  strings:
    $key_2f82 = { 7b ea [2] 0f f2 [2] 48 f0 [2] 0f e1 [2] 41 ed [2] 4d e7 [2] 5a ec [2] 41 a2 [2] 7c }

  condition:
    any of them
}