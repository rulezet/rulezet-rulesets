rule TTP_XOR_MULT_DOSStub_66df {
  strings:
    $key_66df = { 32 b7 [2] 46 af [2] 01 ad [2] 46 bc [2] 08 b0 [2] 04 ba [2] 13 b1 [2] 08 ff [2] 35 }

  condition:
    any of them
}