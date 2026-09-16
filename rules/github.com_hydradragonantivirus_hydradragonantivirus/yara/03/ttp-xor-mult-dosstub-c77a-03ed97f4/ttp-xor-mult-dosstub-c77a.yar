rule TTP_XOR_MULT_DOSStub_c77a {
  strings:
    $key_c77a = { 93 12 [2] e7 0a [2] a0 08 [2] e7 19 [2] a9 15 [2] a5 1f [2] b2 14 [2] a9 5a [2] 94 }

  condition:
    any of them
}