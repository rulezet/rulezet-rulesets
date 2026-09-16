rule TTP_XOR_MULT_DOSStub_de43 {
  strings:
    $key_de43 = { 8a 2b [2] fe 33 [2] b9 31 [2] fe 20 [2] b0 2c [2] bc 26 [2] ab 2d [2] b0 63 [2] 8d }

  condition:
    any of them
}