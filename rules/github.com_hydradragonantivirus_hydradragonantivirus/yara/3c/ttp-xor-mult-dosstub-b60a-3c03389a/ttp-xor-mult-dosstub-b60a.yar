rule TTP_XOR_MULT_DOSStub_b60a {
  strings:
    $key_b60a = { e2 62 [2] 96 7a [2] d1 78 [2] 96 69 [2] d8 65 [2] d4 6f [2] c3 64 [2] d8 2a [2] e5 }

  condition:
    any of them
}