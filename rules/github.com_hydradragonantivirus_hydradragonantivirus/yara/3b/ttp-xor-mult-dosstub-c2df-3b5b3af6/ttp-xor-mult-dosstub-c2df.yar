rule TTP_XOR_MULT_DOSStub_c2df {
  strings:
    $key_c2df = { 96 b7 [2] e2 af [2] a5 ad [2] e2 bc [2] ac b0 [2] a0 ba [2] b7 b1 [2] ac ff [2] 91 }

  condition:
    any of them
}