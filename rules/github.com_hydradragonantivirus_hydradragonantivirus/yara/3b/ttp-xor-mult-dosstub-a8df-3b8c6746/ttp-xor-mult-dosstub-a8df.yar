rule TTP_XOR_MULT_DOSStub_a8df {
  strings:
    $key_a8df = { fc b7 [2] 88 af [2] cf ad [2] 88 bc [2] c6 b0 [2] ca ba [2] dd b1 [2] c6 ff [2] fb }

  condition:
    any of them
}