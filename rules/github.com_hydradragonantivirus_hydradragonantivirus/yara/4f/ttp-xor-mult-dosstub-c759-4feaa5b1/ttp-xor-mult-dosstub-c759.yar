rule TTP_XOR_MULT_DOSStub_c759 {
  strings:
    $key_c759 = { 93 31 [2] e7 29 [2] a0 2b [2] e7 3a [2] a9 36 [2] a5 3c [2] b2 37 [2] a9 79 [2] 94 }

  condition:
    any of them
}