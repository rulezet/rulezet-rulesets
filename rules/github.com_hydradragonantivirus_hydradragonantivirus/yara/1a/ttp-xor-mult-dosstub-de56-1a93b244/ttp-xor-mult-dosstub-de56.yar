rule TTP_XOR_MULT_DOSStub_de56 {
  strings:
    $key_de56 = { 8a 3e [2] fe 26 [2] b9 24 [2] fe 35 [2] b0 39 [2] bc 33 [2] ab 38 [2] b0 76 [2] 8d }

  condition:
    any of them
}