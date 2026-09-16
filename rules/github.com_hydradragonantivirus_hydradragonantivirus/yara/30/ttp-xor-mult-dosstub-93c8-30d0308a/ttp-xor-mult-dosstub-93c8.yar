rule TTP_XOR_MULT_DOSStub_93c8 {
  strings:
    $key_93c8 = { c7 a0 [2] b3 b8 [2] f4 ba [2] b3 ab [2] fd a7 [2] f1 ad [2] e6 a6 [2] fd e8 [2] c0 }

  condition:
    any of them
}