rule TTP_XOR_MULT_DOSStub_b67a {
  strings:
    $key_b67a = { e2 12 [2] 96 0a [2] d1 08 [2] 96 19 [2] d8 15 [2] d4 1f [2] c3 14 [2] d8 5a [2] e5 }

  condition:
    any of them
}