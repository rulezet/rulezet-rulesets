rule TTP_XOR_MULT_DOSStub_de69 {
  strings:
    $key_de69 = { 8a 01 [2] fe 19 [2] b9 1b [2] fe 0a [2] b0 06 [2] bc 0c [2] ab 07 [2] b0 49 [2] 8d }

  condition:
    any of them
}