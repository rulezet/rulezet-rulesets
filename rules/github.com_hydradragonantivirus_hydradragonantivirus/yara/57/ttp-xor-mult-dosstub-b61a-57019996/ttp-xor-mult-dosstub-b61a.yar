rule TTP_XOR_MULT_DOSStub_b61a {
  strings:
    $key_b61a = { e2 72 [2] 96 6a [2] d1 68 [2] 96 79 [2] d8 75 [2] d4 7f [2] c3 74 [2] d8 3a [2] e5 }

  condition:
    any of them
}