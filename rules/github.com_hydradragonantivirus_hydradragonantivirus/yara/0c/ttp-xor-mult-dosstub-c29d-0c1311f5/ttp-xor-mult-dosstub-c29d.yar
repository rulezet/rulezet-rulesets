rule TTP_XOR_MULT_DOSStub_c29d {
  strings:
    $key_c29d = { 96 f5 [2] e2 ed [2] a5 ef [2] e2 fe [2] ac f2 [2] a0 f8 [2] b7 f3 [2] ac bd [2] 91 }

  condition:
    any of them
}