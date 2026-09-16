rule TTP_XOR_MULT_DOSStub_c748 {
  strings:
    $key_c748 = { 93 20 [2] e7 38 [2] a0 3a [2] e7 2b [2] a9 27 [2] a5 2d [2] b2 26 [2] a9 68 [2] 94 }

  condition:
    any of them
}