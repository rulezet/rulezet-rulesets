rule TTP_XOR_MULT_DOSStub_d09d {
  strings:
    $key_d09d = { 84 f5 [2] f0 ed [2] b7 ef [2] f0 fe [2] be f2 [2] b2 f8 [2] a5 f3 [2] be bd [2] 83 }

  condition:
    any of them
}