rule TTP_XOR_MULT_DOSStub_c5df {
  strings:
    $key_c5df = { 91 b7 [2] e5 af [2] a2 ad [2] e5 bc [2] ab b0 [2] a7 ba [2] b0 b1 [2] ab ff [2] 96 }

  condition:
    any of them
}