rule TTP_XOR_MULT_DOSStub_b005 {
  strings:
    $key_b005 = { e4 6d [2] 90 75 [2] d7 77 [2] 90 66 [2] de 6a [2] d2 60 [2] c5 6b [2] de 25 [2] e3 }

  condition:
    any of them
}