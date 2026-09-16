rule TTP_XOR_MULT_DOSStub_81d5 {
  strings:
    $key_81d5 = { d5 bd [2] a1 a5 [2] e6 a7 [2] a1 b6 [2] ef ba [2] e3 b0 [2] f4 bb [2] ef f5 [2] d2 }

  condition:
    any of them
}