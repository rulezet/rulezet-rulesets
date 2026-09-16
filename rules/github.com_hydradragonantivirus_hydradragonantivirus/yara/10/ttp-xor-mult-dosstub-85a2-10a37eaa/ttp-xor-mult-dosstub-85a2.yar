rule TTP_XOR_MULT_DOSStub_85a2 {
  strings:
    $key_85a2 = { d1 ca [2] a5 d2 [2] e2 d0 [2] a5 c1 [2] eb cd [2] e7 c7 [2] f0 cc [2] eb 82 [2] d6 }

  condition:
    any of them
}