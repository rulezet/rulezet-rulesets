rule TTP_XOR_MULT_DOSStub_93b9 {
  strings:
    $key_93b9 = { c7 d1 [2] b3 c9 [2] f4 cb [2] b3 da [2] fd d6 [2] f1 dc [2] e6 d7 [2] fd 99 [2] c0 }

  condition:
    any of them
}