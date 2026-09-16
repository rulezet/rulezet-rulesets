rule TTP_XOR_MULT_DOSStub_b662 {
  strings:
    $key_b662 = { e2 0a [2] 96 12 [2] d1 10 [2] 96 01 [2] d8 0d [2] d4 07 [2] c3 0c [2] d8 42 [2] e5 }

  condition:
    any of them
}