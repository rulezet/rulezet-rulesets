rule TTP_XOR_MULT_DOSStub_d988 {
  strings:
    $key_d988 = { 8d e0 [2] f9 f8 [2] be fa [2] f9 eb [2] b7 e7 [2] bb ed [2] ac e6 [2] b7 a8 [2] 8a }

  condition:
    any of them
}