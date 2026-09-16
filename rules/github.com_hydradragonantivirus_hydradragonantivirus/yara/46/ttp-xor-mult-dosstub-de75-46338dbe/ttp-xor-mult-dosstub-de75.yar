rule TTP_XOR_MULT_DOSStub_de75 {
  strings:
    $key_de75 = { 8a 1d [2] fe 05 [2] b9 07 [2] fe 16 [2] b0 1a [2] bc 10 [2] ab 1b [2] b0 55 [2] 8d }

  condition:
    any of them
}