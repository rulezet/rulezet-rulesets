rule TTP_XOR_MULT_DOSStub_93a4 {
  strings:
    $key_93a4 = { c7 cc [2] b3 d4 [2] f4 d6 [2] b3 c7 [2] fd cb [2] f1 c1 [2] e6 ca [2] fd 84 [2] c0 }

  condition:
    any of them
}