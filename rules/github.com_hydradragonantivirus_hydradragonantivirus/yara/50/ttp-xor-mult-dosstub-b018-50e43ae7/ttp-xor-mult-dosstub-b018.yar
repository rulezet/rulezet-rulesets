rule TTP_XOR_MULT_DOSStub_b018 {
  strings:
    $key_b018 = { e4 70 [2] 90 68 [2] d7 6a [2] 90 7b [2] de 77 [2] d2 7d [2] c5 76 [2] de 38 [2] e3 }

  condition:
    any of them
}