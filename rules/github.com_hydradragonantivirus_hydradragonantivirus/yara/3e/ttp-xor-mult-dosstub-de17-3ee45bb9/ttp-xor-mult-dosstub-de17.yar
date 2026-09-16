rule TTP_XOR_MULT_DOSStub_de17 {
  strings:
    $key_de17 = { 8a 7f [2] fe 67 [2] b9 65 [2] fe 74 [2] b0 78 [2] bc 72 [2] ab 79 [2] b0 37 [2] 8d }

  condition:
    any of them
}