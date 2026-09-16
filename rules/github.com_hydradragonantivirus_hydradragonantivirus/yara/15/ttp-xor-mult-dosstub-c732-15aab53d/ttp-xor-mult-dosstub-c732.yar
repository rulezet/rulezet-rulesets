rule TTP_XOR_MULT_DOSStub_c732 {
  strings:
    $key_c732 = { 93 5a [2] e7 42 [2] a0 40 [2] e7 51 [2] a9 5d [2] a5 57 [2] b2 5c [2] a9 12 [2] 94 }

  condition:
    any of them
}