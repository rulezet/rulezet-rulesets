rule TTP_XOR_MULT_DOSStub_de55 {
  strings:
    $key_de55 = { 8a 3d [2] fe 25 [2] b9 27 [2] fe 36 [2] b0 3a [2] bc 30 [2] ab 3b [2] b0 75 [2] 8d }

  condition:
    any of them
}