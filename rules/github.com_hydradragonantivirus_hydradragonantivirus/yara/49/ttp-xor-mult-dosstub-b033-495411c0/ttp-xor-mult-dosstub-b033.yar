rule TTP_XOR_MULT_DOSStub_b033 {
  strings:
    $key_b033 = { e4 5b [2] 90 43 [2] d7 41 [2] 90 50 [2] de 5c [2] d2 56 [2] c5 5d [2] de 13 [2] e3 }

  condition:
    any of them
}