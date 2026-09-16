rule TTP_XOR_MULT_DOSStub_801a {
  strings:
    $key_801a = { d4 72 [2] a0 6a [2] e7 68 [2] a0 79 [2] ee 75 [2] e2 7f [2] f5 74 [2] ee 3a [2] d3 }

  condition:
    any of them
}