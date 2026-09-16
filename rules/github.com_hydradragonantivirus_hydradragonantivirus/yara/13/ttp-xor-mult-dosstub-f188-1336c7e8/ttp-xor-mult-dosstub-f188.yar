rule TTP_XOR_MULT_DOSStub_f188 {
  strings:
    $key_f188 = { a5 e0 [2] d1 f8 [2] 96 fa [2] d1 eb [2] 9f e7 [2] 93 ed [2] 84 e6 [2] 9f a8 [2] a2 }

  condition:
    any of them
}