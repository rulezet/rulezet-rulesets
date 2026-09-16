rule TTP_XOR_MULT_DOSStub_f588 {
  strings:
    $key_f588 = { a1 e0 [2] d5 f8 [2] 92 fa [2] d5 eb [2] 9b e7 [2] 97 ed [2] 80 e6 [2] 9b a8 [2] a6 }

  condition:
    any of them
}