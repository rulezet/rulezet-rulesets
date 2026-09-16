rule TTP_XOR_MULT_DOSStub_d045 {
  strings:
    $key_d045 = { 84 2d [2] f0 35 [2] b7 37 [2] f0 26 [2] be 2a [2] b2 20 [2] a5 2b [2] be 65 [2] 83 }

  condition:
    any of them
}