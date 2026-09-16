rule TTP_XOR_MULT_DOSStub_deca {
  strings:
    $key_deca = { 8a a2 [2] fe ba [2] b9 b8 [2] fe a9 [2] b0 a5 [2] bc af [2] ab a4 [2] b0 ea [2] 8d }

  condition:
    any of them
}