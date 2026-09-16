rule TTP_XOR_MULT_DOSStub_80be {
  strings:
    $key_80be = { d4 d6 [2] a0 ce [2] e7 cc [2] a0 dd [2] ee d1 [2] e2 db [2] f5 d0 [2] ee 9e [2] d3 }

  condition:
    any of them
}