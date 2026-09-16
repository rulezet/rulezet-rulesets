rule TTP_XOR_MULT_DOSStub_93a9 {
  strings:
    $key_93a9 = { c7 c1 [2] b3 d9 [2] f4 db [2] b3 ca [2] fd c6 [2] f1 cc [2] e6 c7 [2] fd 89 [2] c0 }

  condition:
    any of them
}