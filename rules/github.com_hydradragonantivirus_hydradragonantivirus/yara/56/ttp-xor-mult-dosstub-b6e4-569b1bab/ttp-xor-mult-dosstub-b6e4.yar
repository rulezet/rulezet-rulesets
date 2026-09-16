rule TTP_XOR_MULT_DOSStub_b6e4 {
  strings:
    $key_b6e4 = { e2 8c [2] 96 94 [2] d1 96 [2] 96 87 [2] d8 8b [2] d4 81 [2] c3 8a [2] d8 c4 [2] e5 }

  condition:
    any of them
}