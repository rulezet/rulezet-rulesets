rule TTP_XOR_MULT_DOSStub_b6e2 {
  strings:
    $key_b6e2 = { e2 8a [2] 96 92 [2] d1 90 [2] 96 81 [2] d8 8d [2] d4 87 [2] c3 8c [2] d8 c2 [2] e5 }

  condition:
    any of them
}