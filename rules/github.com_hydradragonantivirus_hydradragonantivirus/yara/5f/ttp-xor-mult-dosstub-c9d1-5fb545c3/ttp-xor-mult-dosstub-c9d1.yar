rule TTP_XOR_MULT_DOSStub_c9d1 {
  strings:
    $key_c9d1 = { 9d b9 [2] e9 a1 [2] ae a3 [2] e9 b2 [2] a7 be [2] ab b4 [2] bc bf [2] a7 f1 [2] 9a }

  condition:
    any of them
}