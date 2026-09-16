rule TTP_XOR_MULT_DOSStub_de0e {
  strings:
    $key_de0e = { 8a 66 [2] fe 7e [2] b9 7c [2] fe 6d [2] b0 61 [2] bc 6b [2] ab 60 [2] b0 2e [2] 8d }

  condition:
    any of them
}