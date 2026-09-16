rule TTP_XOR_MULT_DOSStub_80fc {
  strings:
    $key_80fc = { d4 94 [2] a0 8c [2] e7 8e [2] a0 9f [2] ee 93 [2] e2 99 [2] f5 92 [2] ee dc [2] d3 }

  condition:
    any of them
}