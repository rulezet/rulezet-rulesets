rule TTP_XOR_MULT_DOSStub_85a5 {
  strings:
    $key_85a5 = { d1 cd [2] a5 d5 [2] e2 d7 [2] a5 c6 [2] eb ca [2] e7 c0 [2] f0 cb [2] eb 85 [2] d6 }

  condition:
    any of them
}