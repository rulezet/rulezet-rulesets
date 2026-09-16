rule TTP_XOR_MULT_DOSStub_de11 {
  strings:
    $key_de11 = { 8a 79 [2] fe 61 [2] b9 63 [2] fe 72 [2] b0 7e [2] bc 74 [2] ab 7f [2] b0 31 [2] 8d }

  condition:
    any of them
}