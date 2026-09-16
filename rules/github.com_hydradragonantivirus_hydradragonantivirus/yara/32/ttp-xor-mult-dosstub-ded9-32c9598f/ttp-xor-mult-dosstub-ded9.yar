rule TTP_XOR_MULT_DOSStub_ded9 {
  strings:
    $key_ded9 = { 8a b1 [2] fe a9 [2] b9 ab [2] fe ba [2] b0 b6 [2] bc bc [2] ab b7 [2] b0 f9 [2] 8d }

  condition:
    any of them
}