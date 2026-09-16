rule TTP_XOR_MULT_DOSStub_0982 {
  strings:
    $key_0982 = { 5d ea [2] 29 f2 [2] 6e f0 [2] 29 e1 [2] 67 ed [2] 6b e7 [2] 7c ec [2] 67 a2 [2] 5a }

  condition:
    any of them
}