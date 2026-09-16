rule TTP_XOR_MULT_DOSStub_91a2 {
  strings:
    $key_91a2 = { c5 ca [2] b1 d2 [2] f6 d0 [2] b1 c1 [2] ff cd [2] f3 c7 [2] e4 cc [2] ff 82 [2] c2 }

  condition:
    any of them
}