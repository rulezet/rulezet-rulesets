rule TTP_XOR_MULT_DOSStub_de45 {
  strings:
    $key_de45 = { 8a 2d [2] fe 35 [2] b9 37 [2] fe 26 [2] b0 2a [2] bc 20 [2] ab 2b [2] b0 65 [2] 8d }

  condition:
    any of them
}