rule TTP_XOR_MULT_DOSStub_b035 {
  strings:
    $key_b035 = { e4 5d [2] 90 45 [2] d7 47 [2] 90 56 [2] de 5a [2] d2 50 [2] c5 5b [2] de 15 [2] e3 }

  condition:
    any of them
}