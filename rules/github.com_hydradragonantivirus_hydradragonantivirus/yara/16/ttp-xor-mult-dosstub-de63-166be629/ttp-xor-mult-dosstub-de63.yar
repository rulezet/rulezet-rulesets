rule TTP_XOR_MULT_DOSStub_de63 {
  strings:
    $key_de63 = { 8a 0b [2] fe 13 [2] b9 11 [2] fe 00 [2] b0 0c [2] bc 06 [2] ab 0d [2] b0 43 [2] 8d }

  condition:
    any of them
}