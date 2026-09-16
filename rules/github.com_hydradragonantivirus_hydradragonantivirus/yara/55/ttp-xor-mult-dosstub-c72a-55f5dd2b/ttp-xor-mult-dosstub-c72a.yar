rule TTP_XOR_MULT_DOSStub_c72a {
  strings:
    $key_c72a = { 93 42 [2] e7 5a [2] a0 58 [2] e7 49 [2] a9 45 [2] a5 4f [2] b2 44 [2] a9 0a [2] 94 }

  condition:
    any of them
}