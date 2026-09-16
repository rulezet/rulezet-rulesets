rule TTP_XOR_MULT_DOSStub_b6e9 {
  strings:
    $key_b6e9 = { e2 81 [2] 96 99 [2] d1 9b [2] 96 8a [2] d8 86 [2] d4 8c [2] c3 87 [2] d8 c9 [2] e5 }

  condition:
    any of them
}