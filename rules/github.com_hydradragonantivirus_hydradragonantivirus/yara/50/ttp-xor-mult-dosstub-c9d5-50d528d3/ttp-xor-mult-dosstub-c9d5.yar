rule TTP_XOR_MULT_DOSStub_c9d5 {
  strings:
    $key_c9d5 = { 9d bd [2] e9 a5 [2] ae a7 [2] e9 b6 [2] a7 ba [2] ab b0 [2] bc bb [2] a7 f5 [2] 9a }

  condition:
    any of them
}