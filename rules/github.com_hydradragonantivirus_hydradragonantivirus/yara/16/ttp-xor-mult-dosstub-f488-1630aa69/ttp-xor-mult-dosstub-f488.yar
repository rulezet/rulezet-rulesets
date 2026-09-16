rule TTP_XOR_MULT_DOSStub_f488 {
  strings:
    $key_f488 = { a0 e0 [2] d4 f8 [2] 93 fa [2] d4 eb [2] 9a e7 [2] 96 ed [2] 81 e6 [2] 9a a8 [2] a7 }

  condition:
    any of them
}