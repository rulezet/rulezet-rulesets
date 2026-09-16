rule TTP_XOR_MULT_DOSStub_89df {
  strings:
    $key_89df = { dd b7 [2] a9 af [2] ee ad [2] a9 bc [2] e7 b0 [2] eb ba [2] fc b1 [2] e7 ff [2] da }

  condition:
    any of them
}