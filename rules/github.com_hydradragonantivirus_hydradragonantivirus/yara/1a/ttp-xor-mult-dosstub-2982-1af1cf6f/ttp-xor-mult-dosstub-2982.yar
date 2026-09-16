rule TTP_XOR_MULT_DOSStub_2982 {
  strings:
    $key_2982 = { 7d ea [2] 09 f2 [2] 4e f0 [2] 09 e1 [2] 47 ed [2] 4b e7 [2] 5c ec [2] 47 a2 [2] 7a }

  condition:
    any of them
}