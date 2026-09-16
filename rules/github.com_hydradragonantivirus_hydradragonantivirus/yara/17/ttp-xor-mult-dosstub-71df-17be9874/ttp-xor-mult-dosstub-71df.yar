rule TTP_XOR_MULT_DOSStub_71df {
  strings:
    $key_71df = { 25 b7 [2] 51 af [2] 16 ad [2] 51 bc [2] 1f b0 [2] 13 ba [2] 04 b1 [2] 1f ff [2] 22 }

  condition:
    any of them
}