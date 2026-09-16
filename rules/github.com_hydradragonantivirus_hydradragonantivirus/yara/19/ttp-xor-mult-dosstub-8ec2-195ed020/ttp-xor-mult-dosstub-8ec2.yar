rule TTP_XOR_MULT_DOSStub_8ec2 {
  strings:
    $key_8ec2 = { da aa [2] ae b2 [2] e9 b0 [2] ae a1 [2] e0 ad [2] ec a7 [2] fb ac [2] e0 e2 [2] dd }

  condition:
    any of them
}