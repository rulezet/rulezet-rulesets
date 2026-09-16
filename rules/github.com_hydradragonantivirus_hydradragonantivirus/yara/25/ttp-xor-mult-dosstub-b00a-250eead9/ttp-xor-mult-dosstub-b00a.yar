rule TTP_XOR_MULT_DOSStub_b00a {
  strings:
    $key_b00a = { e4 62 [2] 90 7a [2] d7 78 [2] 90 69 [2] de 65 [2] d2 6f [2] c5 64 [2] de 2a [2] e3 }

  condition:
    any of them
}