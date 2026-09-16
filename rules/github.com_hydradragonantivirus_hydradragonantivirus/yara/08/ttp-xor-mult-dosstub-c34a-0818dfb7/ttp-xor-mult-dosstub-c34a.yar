rule TTP_XOR_MULT_DOSStub_c34a {
  strings:
    $key_c34a = { 97 22 [2] e3 3a [2] a4 38 [2] e3 29 [2] ad 25 [2] a1 2f [2] b6 24 [2] ad 6a [2] 90 }

  condition:
    any of them
}