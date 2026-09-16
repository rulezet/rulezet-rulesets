rule TTP_XOR_MULT_DOSStub_80eb {
  strings:
    $key_80eb = { d4 83 [2] a0 9b [2] e7 99 [2] a0 88 [2] ee 84 [2] e2 8e [2] f5 85 [2] ee cb [2] d3 }

  condition:
    any of them
}