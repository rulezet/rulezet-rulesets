rule TTP_XOR_MULT_DOSStub_c9a3 {
  strings:
    $key_c9a3 = { 9d cb [2] e9 d3 [2] ae d1 [2] e9 c0 [2] a7 cc [2] ab c6 [2] bc cd [2] a7 83 [2] 9a }

  condition:
    any of them
}