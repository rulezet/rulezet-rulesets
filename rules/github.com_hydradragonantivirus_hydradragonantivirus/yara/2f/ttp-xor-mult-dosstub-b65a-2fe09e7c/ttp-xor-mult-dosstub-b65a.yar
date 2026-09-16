rule TTP_XOR_MULT_DOSStub_b65a {
  strings:
    $key_b65a = { e2 32 [2] 96 2a [2] d1 28 [2] 96 39 [2] d8 35 [2] d4 3f [2] c3 34 [2] d8 7a [2] e5 }

  condition:
    any of them
}