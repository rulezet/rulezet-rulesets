rule TTP_XOR_MULT_DOSStub_d0c4 {
  strings:
    $key_d0c4 = { 84 ac [2] f0 b4 [2] b7 b6 [2] f0 a7 [2] be ab [2] b2 a1 [2] a5 aa [2] be e4 [2] 83 }

  condition:
    any of them
}