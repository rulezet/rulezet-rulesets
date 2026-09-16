rule TTP_XOR_MULT_DOSStub_81c3 {
  strings:
    $key_81c3 = { d5 ab [2] a1 b3 [2] e6 b1 [2] a1 a0 [2] ef ac [2] e3 a6 [2] f4 ad [2] ef e3 [2] d2 }

  condition:
    any of them
}