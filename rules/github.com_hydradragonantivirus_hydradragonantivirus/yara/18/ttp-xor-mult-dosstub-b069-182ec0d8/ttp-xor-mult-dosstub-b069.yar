rule TTP_XOR_MULT_DOSStub_b069 {
  strings:
    $key_b069 = { e4 01 [2] 90 19 [2] d7 1b [2] 90 0a [2] de 06 [2] d2 0c [2] c5 07 [2] de 49 [2] e3 }

  condition:
    any of them
}