rule TTP_XOR_MULT_DOSStub_de00 {
  strings:
    $key_de00 = { 8a 68 [2] fe 70 [2] b9 72 [2] fe 63 [2] b0 6f [2] bc 65 [2] ab 6e [2] b0 20 [2] 8d }

  condition:
    any of them
}