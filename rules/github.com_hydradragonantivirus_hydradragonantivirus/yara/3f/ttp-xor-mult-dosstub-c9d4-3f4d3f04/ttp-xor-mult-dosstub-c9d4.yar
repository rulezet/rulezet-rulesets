rule TTP_XOR_MULT_DOSStub_c9d4 {
  strings:
    $key_c9d4 = { 9d bc [2] e9 a4 [2] ae a6 [2] e9 b7 [2] a7 bb [2] ab b1 [2] bc ba [2] a7 f4 [2] 9a }

  condition:
    any of them
}