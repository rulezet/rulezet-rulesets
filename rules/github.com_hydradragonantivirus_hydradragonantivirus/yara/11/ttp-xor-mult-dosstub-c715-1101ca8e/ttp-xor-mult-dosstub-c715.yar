rule TTP_XOR_MULT_DOSStub_c715 {
  strings:
    $key_c715 = { 93 7d [2] e7 65 [2] a0 67 [2] e7 76 [2] a9 7a [2] a5 70 [2] b2 7b [2] a9 35 [2] 94 }

  condition:
    any of them
}