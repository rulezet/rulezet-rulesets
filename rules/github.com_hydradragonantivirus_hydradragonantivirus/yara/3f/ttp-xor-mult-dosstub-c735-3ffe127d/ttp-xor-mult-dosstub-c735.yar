rule TTP_XOR_MULT_DOSStub_c735 {
  strings:
    $key_c735 = { 93 5d [2] e7 45 [2] a0 47 [2] e7 56 [2] a9 5a [2] a5 50 [2] b2 5b [2] a9 15 [2] 94 }

  condition:
    any of them
}