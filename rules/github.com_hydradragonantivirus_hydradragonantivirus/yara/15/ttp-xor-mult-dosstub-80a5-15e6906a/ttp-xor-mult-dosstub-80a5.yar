rule TTP_XOR_MULT_DOSStub_80a5 {
  strings:
    $key_80a5 = { d4 cd [2] a0 d5 [2] e7 d7 [2] a0 c6 [2] ee ca [2] e2 c0 [2] f5 cb [2] ee 85 [2] d3 }

  condition:
    any of them
}