rule TTP_XOR_MULT_DOSStub_b272 {
  strings:
    $key_b272 = { e6 1a [2] 92 02 [2] d5 00 [2] 92 11 [2] dc 1d [2] d0 17 [2] c7 1c [2] dc 52 [2] e1 }

  condition:
    any of them
}