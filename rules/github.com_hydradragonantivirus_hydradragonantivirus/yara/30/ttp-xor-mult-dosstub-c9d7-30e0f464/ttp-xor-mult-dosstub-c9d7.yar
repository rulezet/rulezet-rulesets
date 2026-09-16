rule TTP_XOR_MULT_DOSStub_c9d7 {
  strings:
    $key_c9d7 = { 9d bf [2] e9 a7 [2] ae a5 [2] e9 b4 [2] a7 b8 [2] ab b2 [2] bc b9 [2] a7 f7 [2] 9a }

  condition:
    any of them
}