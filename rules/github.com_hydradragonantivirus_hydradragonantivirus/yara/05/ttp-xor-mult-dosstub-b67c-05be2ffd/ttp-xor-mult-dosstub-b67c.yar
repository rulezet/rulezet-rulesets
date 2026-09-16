rule TTP_XOR_MULT_DOSStub_b67c {
  strings:
    $key_b67c = { e2 14 [2] 96 0c [2] d1 0e [2] 96 1f [2] d8 13 [2] d4 19 [2] c3 12 [2] d8 5c [2] e5 }

  condition:
    any of them
}