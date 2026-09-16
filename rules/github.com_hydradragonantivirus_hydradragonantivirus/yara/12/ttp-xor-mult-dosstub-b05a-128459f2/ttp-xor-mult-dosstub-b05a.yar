rule TTP_XOR_MULT_DOSStub_b05a {
  strings:
    $key_b05a = { e4 32 [2] 90 2a [2] d7 28 [2] 90 39 [2] de 35 [2] d2 3f [2] c5 34 [2] de 7a [2] e3 }

  condition:
    any of them
}