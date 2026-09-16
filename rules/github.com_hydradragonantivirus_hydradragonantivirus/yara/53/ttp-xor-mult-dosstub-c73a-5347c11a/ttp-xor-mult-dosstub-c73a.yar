rule TTP_XOR_MULT_DOSStub_c73a {
  strings:
    $key_c73a = { 93 52 [2] e7 4a [2] a0 48 [2] e7 59 [2] a9 55 [2] a5 5f [2] b2 54 [2] a9 1a [2] 94 }

  condition:
    any of them
}