rule TTP_XOR_MULT_DOSStub_b039 {
  strings:
    $key_b039 = { e4 51 [2] 90 49 [2] d7 4b [2] 90 5a [2] de 56 [2] d2 5c [2] c5 57 [2] de 19 [2] e3 }

  condition:
    any of them
}