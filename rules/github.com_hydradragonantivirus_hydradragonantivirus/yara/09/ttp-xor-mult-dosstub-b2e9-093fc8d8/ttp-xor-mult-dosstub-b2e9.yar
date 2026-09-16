rule TTP_XOR_MULT_DOSStub_b2e9 {
  strings:
    $key_b2e9 = { e6 81 [2] 92 99 [2] d5 9b [2] 92 8a [2] dc 86 [2] d0 8c [2] c7 87 [2] dc c9 [2] e1 }

  condition:
    any of them
}