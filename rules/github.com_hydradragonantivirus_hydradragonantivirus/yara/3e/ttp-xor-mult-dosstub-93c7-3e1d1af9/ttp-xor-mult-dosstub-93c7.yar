rule TTP_XOR_MULT_DOSStub_93c7 {
  strings:
    $key_93c7 = { c7 af [2] b3 b7 [2] f4 b5 [2] b3 a4 [2] fd a8 [2] f1 a2 [2] e6 a9 [2] fd e7 [2] c0 }

  condition:
    any of them
}