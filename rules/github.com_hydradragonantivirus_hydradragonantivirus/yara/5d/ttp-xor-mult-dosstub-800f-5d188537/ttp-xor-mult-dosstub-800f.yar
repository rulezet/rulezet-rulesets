rule TTP_XOR_MULT_DOSStub_800f {
  strings:
    $key_800f = { d4 67 [2] a0 7f [2] e7 7d [2] a0 6c [2] ee 60 [2] e2 6a [2] f5 61 [2] ee 2f [2] d3 }

  condition:
    any of them
}