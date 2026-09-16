rule TTP_XOR_MULT_DOSStub_deb6 {
  strings:
    $key_deb6 = { 8a de [2] fe c6 [2] b9 c4 [2] fe d5 [2] b0 d9 [2] bc d3 [2] ab d8 [2] b0 96 [2] 8d }

  condition:
    any of them
}