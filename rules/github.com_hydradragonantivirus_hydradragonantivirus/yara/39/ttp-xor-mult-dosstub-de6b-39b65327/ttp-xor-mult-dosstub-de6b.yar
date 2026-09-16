rule TTP_XOR_MULT_DOSStub_de6b {
  strings:
    $key_de6b = { 8a 03 [2] fe 1b [2] b9 19 [2] fe 08 [2] b0 04 [2] bc 0e [2] ab 05 [2] b0 4b [2] 8d }

  condition:
    any of them
}