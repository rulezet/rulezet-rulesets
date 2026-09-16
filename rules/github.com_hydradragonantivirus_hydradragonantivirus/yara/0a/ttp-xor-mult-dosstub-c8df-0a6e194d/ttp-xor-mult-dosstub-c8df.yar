rule TTP_XOR_MULT_DOSStub_c8df {
  strings:
    $key_c8df = { 9c b7 [2] e8 af [2] af ad [2] e8 bc [2] a6 b0 [2] aa ba [2] bd b1 [2] a6 ff [2] 9b }

  condition:
    any of them
}