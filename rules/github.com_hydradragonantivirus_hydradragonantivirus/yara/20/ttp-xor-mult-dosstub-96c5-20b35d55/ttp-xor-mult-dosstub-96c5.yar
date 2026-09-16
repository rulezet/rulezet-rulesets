rule TTP_XOR_MULT_DOSStub_96c5 {
  strings:
    $key_96c5 = { c2 ad [2] b6 b5 [2] f1 b7 [2] b6 a6 [2] f8 aa [2] f4 a0 [2] e3 ab [2] f8 e5 [2] c5 }

  condition:
    any of them
}