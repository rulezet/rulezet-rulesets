rule TTP_XOR_MULT_DOSStub_de58 {
  strings:
    $key_de58 = { 8a 30 [2] fe 28 [2] b9 2a [2] fe 3b [2] b0 37 [2] bc 3d [2] ab 36 [2] b0 78 [2] 8d }

  condition:
    any of them
}