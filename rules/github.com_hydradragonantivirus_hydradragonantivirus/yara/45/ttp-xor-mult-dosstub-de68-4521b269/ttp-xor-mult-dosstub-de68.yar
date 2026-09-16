rule TTP_XOR_MULT_DOSStub_de68 {
  strings:
    $key_de68 = { 8a 00 [2] fe 18 [2] b9 1a [2] fe 0b [2] b0 07 [2] bc 0d [2] ab 06 [2] b0 48 [2] 8d }

  condition:
    any of them
}