rule TTP_XOR_MULT_DOSStub_d59d {
  strings:
    $key_d59d = { 81 f5 [2] f5 ed [2] b2 ef [2] f5 fe [2] bb f2 [2] b7 f8 [2] a0 f3 [2] bb bd [2] 86 }

  condition:
    any of them
}