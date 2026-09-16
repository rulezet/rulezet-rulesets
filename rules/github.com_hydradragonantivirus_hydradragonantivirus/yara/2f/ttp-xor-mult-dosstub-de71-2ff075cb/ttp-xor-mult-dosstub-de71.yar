rule TTP_XOR_MULT_DOSStub_de71 {
  strings:
    $key_de71 = { 8a 19 [2] fe 01 [2] b9 03 [2] fe 12 [2] b0 1e [2] bc 14 [2] ab 1f [2] b0 51 [2] 8d }

  condition:
    any of them
}