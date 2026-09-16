rule TTP_XOR_MULT_DOSStub_92a5 {
  strings:
    $key_92a5 = { c6 cd [2] b2 d5 [2] f5 d7 [2] b2 c6 [2] fc ca [2] f0 c0 [2] e7 cb [2] fc 85 [2] c1 }

  condition:
    any of them
}