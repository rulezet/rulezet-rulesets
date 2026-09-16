rule TTP_XOR_MULT_DOSStub_f288 {
  strings:
    $key_f288 = { a6 e0 [2] d2 f8 [2] 95 fa [2] d2 eb [2] 9c e7 [2] 90 ed [2] 87 e6 [2] 9c a8 [2] a1 }

  condition:
    any of them
}