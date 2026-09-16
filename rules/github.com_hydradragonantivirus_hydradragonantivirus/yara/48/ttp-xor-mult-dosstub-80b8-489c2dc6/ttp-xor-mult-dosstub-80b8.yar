rule TTP_XOR_MULT_DOSStub_80b8 {
  strings:
    $key_80b8 = { d4 d0 [2] a0 c8 [2] e7 ca [2] a0 db [2] ee d7 [2] e2 dd [2] f5 d6 [2] ee 98 [2] d3 }

  condition:
    any of them
}