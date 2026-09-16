rule TTP_XOR_MULT_DOSStub_c708 {
  strings:
    $key_c708 = { 93 60 [2] e7 78 [2] a0 7a [2] e7 6b [2] a9 67 [2] a5 6d [2] b2 66 [2] a9 28 [2] 94 }

  condition:
    any of them
}