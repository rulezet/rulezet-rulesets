rule TTP_XOR_MULT_DOSStub_c7fa {
  strings:
    $key_c7fa = { 93 92 [2] e7 8a [2] a0 88 [2] e7 99 [2] a9 95 [2] a5 9f [2] b2 94 [2] a9 da [2] 94 }

  condition:
    any of them
}