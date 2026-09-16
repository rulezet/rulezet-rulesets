rule TTP_XOR_MULT_DOSStub_c71f {
  strings:
    $key_c71f = { 93 77 [2] e7 6f [2] a0 6d [2] e7 7c [2] a9 70 [2] a5 7a [2] b2 71 [2] a9 3f [2] 94 }

  condition:
    any of them
}