rule TTP_XOR_MULT_DOSStub_de78 {
  strings:
    $key_de78 = { 8a 10 [2] fe 08 [2] b9 0a [2] fe 1b [2] b0 17 [2] bc 1d [2] ab 16 [2] b0 58 [2] 8d }

  condition:
    any of them
}