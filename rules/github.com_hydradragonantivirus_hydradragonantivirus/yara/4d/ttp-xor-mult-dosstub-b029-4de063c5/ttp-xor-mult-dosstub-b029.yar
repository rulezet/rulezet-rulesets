rule TTP_XOR_MULT_DOSStub_b029 {
  strings:
    $key_b029 = { e4 41 [2] 90 59 [2] d7 5b [2] 90 4a [2] de 46 [2] d2 4c [2] c5 47 [2] de 09 [2] e3 }

  condition:
    any of them
}