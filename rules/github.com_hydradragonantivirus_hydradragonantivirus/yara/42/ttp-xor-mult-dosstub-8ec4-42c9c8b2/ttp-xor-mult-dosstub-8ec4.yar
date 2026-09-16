rule TTP_XOR_MULT_DOSStub_8ec4 {
  strings:
    $key_8ec4 = { da ac [2] ae b4 [2] e9 b6 [2] ae a7 [2] e0 ab [2] ec a1 [2] fb aa [2] e0 e4 [2] dd }

  condition:
    any of them
}