rule TTP_XOR_MULT_DOSStub_80ad {
  strings:
    $key_80ad = { d4 c5 [2] a0 dd [2] e7 df [2] a0 ce [2] ee c2 [2] e2 c8 [2] f5 c3 [2] ee 8d [2] d3 }

  condition:
    any of them
}