rule TTP_XOR_MULT_DOSStub_dea9 {
  strings:
    $key_dea9 = { 8a c1 [2] fe d9 [2] b9 db [2] fe ca [2] b0 c6 [2] bc cc [2] ab c7 [2] b0 89 [2] 8d }

  condition:
    any of them
}