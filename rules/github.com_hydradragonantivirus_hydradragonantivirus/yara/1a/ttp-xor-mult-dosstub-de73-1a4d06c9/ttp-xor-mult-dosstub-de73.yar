rule TTP_XOR_MULT_DOSStub_de73 {
  strings:
    $key_de73 = { 8a 1b [2] fe 03 [2] b9 01 [2] fe 10 [2] b0 1c [2] bc 16 [2] ab 1d [2] b0 53 [2] 8d }

  condition:
    any of them
}