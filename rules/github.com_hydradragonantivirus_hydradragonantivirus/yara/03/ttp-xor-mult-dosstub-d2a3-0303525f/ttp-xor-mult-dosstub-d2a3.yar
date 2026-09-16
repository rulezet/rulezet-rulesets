rule TTP_XOR_MULT_DOSStub_d2a3 {
  strings:
    $key_d2a3 = { 86 cb [2] f2 d3 [2] b5 d1 [2] f2 c0 [2] bc cc [2] b0 c6 [2] a7 cd [2] bc 83 [2] 81 }

  condition:
    any of them
}