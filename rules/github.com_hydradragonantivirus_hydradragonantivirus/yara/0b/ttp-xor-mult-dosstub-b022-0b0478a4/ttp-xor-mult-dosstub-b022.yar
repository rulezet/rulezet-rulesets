rule TTP_XOR_MULT_DOSStub_b022 {
  strings:
    $key_b022 = { e4 4a [2] 90 52 [2] d7 50 [2] 90 41 [2] de 4d [2] d2 47 [2] c5 4c [2] de 02 [2] e3 }

  condition:
    any of them
}