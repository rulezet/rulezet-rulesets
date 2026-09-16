rule TTP_XOR_MULT_DOSStub_d0a2 {
  strings:
    $key_d0a2 = { 84 ca [2] f0 d2 [2] b7 d0 [2] f0 c1 [2] be cd [2] b2 c7 [2] a5 cc [2] be 82 [2] 83 }

  condition:
    any of them
}