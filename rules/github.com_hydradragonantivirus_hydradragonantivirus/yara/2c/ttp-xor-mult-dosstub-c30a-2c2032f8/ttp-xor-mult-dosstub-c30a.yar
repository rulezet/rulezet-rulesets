rule TTP_XOR_MULT_DOSStub_c30a {
  strings:
    $key_c30a = { 97 62 [2] e3 7a [2] a4 78 [2] e3 69 [2] ad 65 [2] a1 6f [2] b6 64 [2] ad 2a [2] 90 }

  condition:
    any of them
}