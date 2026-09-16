rule TTP_XOR_MULT_DOSStub_b019 {
  strings:
    $key_b019 = { e4 71 [2] 90 69 [2] d7 6b [2] 90 7a [2] de 76 [2] d2 7c [2] c5 77 [2] de 39 [2] e3 }

  condition:
    any of them
}