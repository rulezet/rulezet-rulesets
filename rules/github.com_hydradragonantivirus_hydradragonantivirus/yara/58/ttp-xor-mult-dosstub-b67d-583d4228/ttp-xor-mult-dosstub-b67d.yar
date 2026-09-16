rule TTP_XOR_MULT_DOSStub_b67d {
  strings:
    $key_b67d = { e2 15 [2] 96 0d [2] d1 0f [2] 96 1e [2] d8 12 [2] d4 18 [2] c3 13 [2] d8 5d [2] e5 }

  condition:
    any of them
}