rule TTP_XOR_MULT_DOSStub_b2e4 {
  strings:
    $key_b2e4 = { e6 8c [2] 92 94 [2] d5 96 [2] 92 87 [2] dc 8b [2] d0 81 [2] c7 8a [2] dc c4 [2] e1 }

  condition:
    any of them
}