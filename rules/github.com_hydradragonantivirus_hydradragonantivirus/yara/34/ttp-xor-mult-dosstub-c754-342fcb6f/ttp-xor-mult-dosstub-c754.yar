rule TTP_XOR_MULT_DOSStub_c754 {
  strings:
    $key_c754 = { 93 3c [2] e7 24 [2] a0 26 [2] e7 37 [2] a9 3b [2] a5 31 [2] b2 3a [2] a9 74 [2] 94 }

  condition:
    any of them
}