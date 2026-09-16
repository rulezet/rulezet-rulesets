rule TTP_XOR_MULT_DOSStub_de35 {
  strings:
    $key_de35 = { 8a 5d [2] fe 45 [2] b9 47 [2] fe 56 [2] b0 5a [2] bc 50 [2] ab 5b [2] b0 15 [2] 8d }

  condition:
    any of them
}