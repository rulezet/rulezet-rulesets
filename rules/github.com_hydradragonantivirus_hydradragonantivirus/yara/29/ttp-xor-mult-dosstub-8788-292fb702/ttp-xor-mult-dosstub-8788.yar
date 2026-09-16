rule TTP_XOR_MULT_DOSStub_8788 {
  strings:
    $key_8788 = { d3 e0 [2] a7 f8 [2] e0 fa [2] a7 eb [2] e9 e7 [2] e5 ed [2] f2 e6 [2] e9 a8 [2] d4 }

  condition:
    any of them
}