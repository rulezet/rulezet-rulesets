rule TTP_XOR_MULT_DOSStub_b07f {
  strings:
    $key_b07f = { e4 17 [2] 90 0f [2] d7 0d [2] 90 1c [2] de 10 [2] d2 1a [2] c5 11 [2] de 5f [2] e3 }

  condition:
    any of them
}