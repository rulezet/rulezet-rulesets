rule TTP_XOR_MULT_DOSStub_93a0 {
  strings:
    $key_93a0 = { c7 c8 [2] b3 d0 [2] f4 d2 [2] b3 c3 [2] fd cf [2] f1 c5 [2] e6 ce [2] fd 80 [2] c0 }

  condition:
    any of them
}