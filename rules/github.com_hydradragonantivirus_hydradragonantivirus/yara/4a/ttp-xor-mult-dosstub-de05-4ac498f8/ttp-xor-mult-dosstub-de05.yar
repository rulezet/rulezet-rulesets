rule TTP_XOR_MULT_DOSStub_de05 {
  strings:
    $key_de05 = { 8a 6d [2] fe 75 [2] b9 77 [2] fe 66 [2] b0 6a [2] bc 60 [2] ab 6b [2] b0 25 [2] 8d }

  condition:
    any of them
}