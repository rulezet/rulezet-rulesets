rule TTP_XOR_MULT_DOSStub_c71a {
  strings:
    $key_c71a = { 93 72 [2] e7 6a [2] a0 68 [2] e7 79 [2] a9 75 [2] a5 7f [2] b2 74 [2] a9 3a [2] 94 }

  condition:
    any of them
}