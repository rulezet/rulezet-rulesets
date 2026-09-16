rule TTP_XOR_MULT_DOSStub_8185 {
  strings:
    $key_8185 = { d5 ed [2] a1 f5 [2] e6 f7 [2] a1 e6 [2] ef ea [2] e3 e0 [2] f4 eb [2] ef a5 [2] d2 }

  condition:
    any of them
}