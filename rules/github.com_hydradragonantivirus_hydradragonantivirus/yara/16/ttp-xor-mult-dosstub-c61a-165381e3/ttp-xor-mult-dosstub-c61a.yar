rule TTP_XOR_MULT_DOSStub_c61a {
  strings:
    $key_c61a = { 92 72 [2] e6 6a [2] a1 68 [2] e6 79 [2] a8 75 [2] a4 7f [2] b3 74 [2] a8 3a [2] 95 }

  condition:
    any of them
}