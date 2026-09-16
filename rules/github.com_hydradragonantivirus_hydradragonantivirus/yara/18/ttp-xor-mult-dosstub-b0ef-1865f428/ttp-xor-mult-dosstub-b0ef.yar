rule TTP_XOR_MULT_DOSStub_b0ef {
  strings:
    $key_b0ef = { e4 87 [2] 90 9f [2] d7 9d [2] 90 8c [2] de 80 [2] d2 8a [2] c5 81 [2] de cf [2] e3 }

  condition:
    any of them
}