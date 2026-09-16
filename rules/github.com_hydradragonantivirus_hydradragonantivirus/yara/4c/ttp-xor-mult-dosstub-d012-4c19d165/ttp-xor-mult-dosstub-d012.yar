rule TTP_XOR_MULT_DOSStub_d012 {
  strings:
    $key_d012 = { 84 7a [2] f0 62 [2] b7 60 [2] f0 71 [2] be 7d [2] b2 77 [2] a5 7c [2] be 32 [2] 83 }

  condition:
    any of them
}