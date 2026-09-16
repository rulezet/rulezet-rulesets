rule TTP_XOR_MULT_DOSStub_c37d {
  strings:
    $key_c37d = { 97 15 [2] e3 0d [2] a4 0f [2] e3 1e [2] ad 12 [2] a1 18 [2] b6 13 [2] ad 5d [2] 90 }

  condition:
    any of them
}