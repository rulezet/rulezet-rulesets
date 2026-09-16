rule TTP_XOR_MULT_DOSStub_93c3 {
  strings:
    $key_93c3 = { c7 ab [2] b3 b3 [2] f4 b1 [2] b3 a0 [2] fd ac [2] f1 a6 [2] e6 ad [2] fd e3 [2] c0 }

  condition:
    any of them
}