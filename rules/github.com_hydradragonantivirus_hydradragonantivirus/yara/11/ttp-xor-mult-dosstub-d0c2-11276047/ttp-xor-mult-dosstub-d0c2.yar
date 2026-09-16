rule TTP_XOR_MULT_DOSStub_d0c2 {
  strings:
    $key_d0c2 = { 84 aa [2] f0 b2 [2] b7 b0 [2] f0 a1 [2] be ad [2] b2 a7 [2] a5 ac [2] be e2 [2] 83 }

  condition:
    any of them
}