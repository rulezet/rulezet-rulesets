rule TTP_XOR_MULT_DOSStub_d0a4 {
  strings:
    $key_d0a4 = { 84 cc [2] f0 d4 [2] b7 d6 [2] f0 c7 [2] be cb [2] b2 c1 [2] a5 ca [2] be 84 [2] 83 }

  condition:
    any of them
}