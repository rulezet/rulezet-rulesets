rule TTP_XOR_MULT_DOSStub_c288 {
  strings:
    $key_c288 = { 96 e0 [2] e2 f8 [2] a5 fa [2] e2 eb [2] ac e7 [2] a0 ed [2] b7 e6 [2] ac a8 [2] 91 }

  condition:
    any of them
}