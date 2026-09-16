rule TTP_XOR_MULT_DOSStub_c33a {
  strings:
    $key_c33a = { 97 52 [2] e3 4a [2] a4 48 [2] e3 59 [2] ad 55 [2] a1 5f [2] b6 54 [2] ad 1a [2] 90 }

  condition:
    any of them
}