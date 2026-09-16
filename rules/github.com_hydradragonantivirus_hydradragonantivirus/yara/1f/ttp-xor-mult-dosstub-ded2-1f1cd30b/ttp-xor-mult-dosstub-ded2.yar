rule TTP_XOR_MULT_DOSStub_ded2 {
  strings:
    $key_ded2 = { 8a ba [2] fe a2 [2] b9 a0 [2] fe b1 [2] b0 bd [2] bc b7 [2] ab bc [2] b0 f2 [2] 8d }

  condition:
    any of them
}