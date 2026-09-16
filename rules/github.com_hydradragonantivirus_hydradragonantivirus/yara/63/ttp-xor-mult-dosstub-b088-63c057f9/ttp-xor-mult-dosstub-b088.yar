rule TTP_XOR_MULT_DOSStub_b088 {
  strings:
    $key_b088 = { e4 e0 [2] 90 f8 [2] d7 fa [2] 90 eb [2] de e7 [2] d2 ed [2] c5 e6 [2] de a8 [2] e3 }

  condition:
    any of them
}