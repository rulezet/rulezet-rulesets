rule TTP_XOR_MULT_DOSStub_80f8 {
  strings:
    $key_80f8 = { d4 90 [2] a0 88 [2] e7 8a [2] a0 9b [2] ee 97 [2] e2 9d [2] f5 96 [2] ee d8 [2] d3 }

  condition:
    any of them
}