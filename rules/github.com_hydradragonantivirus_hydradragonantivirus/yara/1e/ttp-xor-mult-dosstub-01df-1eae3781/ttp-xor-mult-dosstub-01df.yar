rule TTP_XOR_MULT_DOSStub_01df {
  strings:
    $key_01df = { 55 b7 [2] 21 af [2] 66 ad [2] 21 bc [2] 6f b0 [2] 63 ba [2] 74 b1 [2] 6f ff [2] 52 }

  condition:
    any of them
}