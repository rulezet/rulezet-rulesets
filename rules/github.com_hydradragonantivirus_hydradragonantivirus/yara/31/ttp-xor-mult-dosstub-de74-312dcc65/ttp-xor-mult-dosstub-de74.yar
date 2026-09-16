rule TTP_XOR_MULT_DOSStub_de74 {
  strings:
    $key_de74 = { 8a 1c [2] fe 04 [2] b9 06 [2] fe 17 [2] b0 1b [2] bc 11 [2] ab 1a [2] b0 54 [2] 8d }

  condition:
    any of them
}