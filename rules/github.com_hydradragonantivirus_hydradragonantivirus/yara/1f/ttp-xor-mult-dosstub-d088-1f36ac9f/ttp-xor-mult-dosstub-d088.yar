rule TTP_XOR_MULT_DOSStub_d088 {
  strings:
    $key_d088 = { 84 e0 [2] f0 f8 [2] b7 fa [2] f0 eb [2] be e7 [2] b2 ed [2] a5 e6 [2] be a8 [2] 83 }

  condition:
    any of them
}