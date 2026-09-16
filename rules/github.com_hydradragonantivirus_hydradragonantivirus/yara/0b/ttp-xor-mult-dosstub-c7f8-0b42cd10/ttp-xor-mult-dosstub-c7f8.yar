rule TTP_XOR_MULT_DOSStub_c7f8 {
  strings:
    $key_c7f8 = { 93 90 [2] e7 88 [2] a0 8a [2] e7 9b [2] a9 97 [2] a5 9d [2] b2 96 [2] a9 d8 [2] 94 }

  condition:
    any of them
}