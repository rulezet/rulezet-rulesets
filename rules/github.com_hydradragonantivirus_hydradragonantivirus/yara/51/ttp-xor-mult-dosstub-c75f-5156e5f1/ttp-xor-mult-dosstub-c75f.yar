rule TTP_XOR_MULT_DOSStub_c75f {
  strings:
    $key_c75f = { 93 37 [2] e7 2f [2] a0 2d [2] e7 3c [2] a9 30 [2] a5 3a [2] b2 31 [2] a9 7f [2] 94 }

  condition:
    any of them
}