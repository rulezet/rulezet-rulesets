rule TTP_XOR_MULT_DOSStub_de06 {
  strings:
    $key_de06 = { 8a 6e [2] fe 76 [2] b9 74 [2] fe 65 [2] b0 69 [2] bc 63 [2] ab 68 [2] b0 26 [2] 8d }

  condition:
    any of them
}