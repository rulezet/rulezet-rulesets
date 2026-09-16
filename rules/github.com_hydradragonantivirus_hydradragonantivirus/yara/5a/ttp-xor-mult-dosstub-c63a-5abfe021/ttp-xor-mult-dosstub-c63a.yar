rule TTP_XOR_MULT_DOSStub_c63a {
  strings:
    $key_c63a = { 92 52 [2] e6 4a [2] a1 48 [2] e6 59 [2] a8 55 [2] a4 5f [2] b3 54 [2] a8 1a [2] 95 }

  condition:
    any of them
}