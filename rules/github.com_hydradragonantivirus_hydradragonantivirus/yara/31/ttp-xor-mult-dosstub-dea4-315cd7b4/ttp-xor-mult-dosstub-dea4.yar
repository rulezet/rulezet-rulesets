rule TTP_XOR_MULT_DOSStub_dea4 {
  strings:
    $key_dea4 = { 8a cc [2] fe d4 [2] b9 d6 [2] fe c7 [2] b0 cb [2] bc c1 [2] ab ca [2] b0 84 [2] 8d }

  condition:
    any of them
}