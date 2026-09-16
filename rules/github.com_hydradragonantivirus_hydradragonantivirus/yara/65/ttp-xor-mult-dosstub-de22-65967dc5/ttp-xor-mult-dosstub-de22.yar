rule TTP_XOR_MULT_DOSStub_de22 {
  strings:
    $key_de22 = { 8a 4a [2] fe 52 [2] b9 50 [2] fe 41 [2] b0 4d [2] bc 47 [2] ab 4c [2] b0 02 [2] 8d }

  condition:
    any of them
}