rule TTP_XOR_MULT_DOSStub_80f9 {
  strings:
    $key_80f9 = { d4 91 [2] a0 89 [2] e7 8b [2] a0 9a [2] ee 96 [2] e2 9c [2] f5 97 [2] ee d9 [2] d3 }

  condition:
    any of them
}