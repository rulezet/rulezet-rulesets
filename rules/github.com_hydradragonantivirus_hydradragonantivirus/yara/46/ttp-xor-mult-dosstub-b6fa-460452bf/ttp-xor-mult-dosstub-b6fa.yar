rule TTP_XOR_MULT_DOSStub_b6fa {
  strings:
    $key_b6fa = { e2 92 [2] 96 8a [2] d1 88 [2] 96 99 [2] d8 95 [2] d4 9f [2] c3 94 [2] d8 da [2] e5 }

  condition:
    any of them
}