rule TTP_XOR_MULT_DOSStub_de52 {
  strings:
    $key_de52 = { 8a 3a [2] fe 22 [2] b9 20 [2] fe 31 [2] b0 3d [2] bc 37 [2] ab 3c [2] b0 72 [2] 8d }

  condition:
    any of them
}