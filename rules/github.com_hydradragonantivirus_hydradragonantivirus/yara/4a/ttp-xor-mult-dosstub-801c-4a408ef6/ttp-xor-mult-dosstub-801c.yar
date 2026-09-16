rule TTP_XOR_MULT_DOSStub_801c {
  strings:
    $key_801c = { d4 74 [2] a0 6c [2] e7 6e [2] a0 7f [2] ee 73 [2] e2 79 [2] f5 72 [2] ee 3c [2] d3 }

  condition:
    any of them
}