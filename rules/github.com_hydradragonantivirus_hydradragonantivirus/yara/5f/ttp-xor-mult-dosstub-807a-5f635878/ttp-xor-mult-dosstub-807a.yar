rule TTP_XOR_MULT_DOSStub_807a {
  strings:
    $key_807a = { d4 12 [2] a0 0a [2] e7 08 [2] a0 19 [2] ee 15 [2] e2 1f [2] f5 14 [2] ee 5a [2] d3 }

  condition:
    any of them
}