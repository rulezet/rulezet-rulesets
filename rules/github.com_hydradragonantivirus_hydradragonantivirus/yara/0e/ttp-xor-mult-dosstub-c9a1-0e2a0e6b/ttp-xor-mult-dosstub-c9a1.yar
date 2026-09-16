rule TTP_XOR_MULT_DOSStub_c9a1 {
  strings:
    $key_c9a1 = { 9d c9 [2] e9 d1 [2] ae d3 [2] e9 c2 [2] a7 ce [2] ab c4 [2] bc cf [2] a7 81 [2] 9a }

  condition:
    any of them
}