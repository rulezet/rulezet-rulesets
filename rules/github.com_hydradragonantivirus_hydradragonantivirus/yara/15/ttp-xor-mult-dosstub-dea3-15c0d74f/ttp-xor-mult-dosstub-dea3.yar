rule TTP_XOR_MULT_DOSStub_dea3 {
  strings:
    $key_dea3 = { 8a cb [2] fe d3 [2] b9 d1 [2] fe c0 [2] b0 cc [2] bc c6 [2] ab cd [2] b0 83 [2] 8d }

  condition:
    any of them
}