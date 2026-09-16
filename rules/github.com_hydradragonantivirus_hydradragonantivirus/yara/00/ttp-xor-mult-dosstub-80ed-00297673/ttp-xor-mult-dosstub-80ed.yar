rule TTP_XOR_MULT_DOSStub_80ed {
  strings:
    $key_80ed = { d4 85 [2] a0 9d [2] e7 9f [2] a0 8e [2] ee 82 [2] e2 88 [2] f5 83 [2] ee cd [2] d3 }

  condition:
    any of them
}