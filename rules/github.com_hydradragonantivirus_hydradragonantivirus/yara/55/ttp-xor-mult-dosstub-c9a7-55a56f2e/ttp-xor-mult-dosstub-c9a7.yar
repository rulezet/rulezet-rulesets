rule TTP_XOR_MULT_DOSStub_c9a7 {
  strings:
    $key_c9a7 = { 9d cf [2] e9 d7 [2] ae d5 [2] e9 c4 [2] a7 c8 [2] ab c2 [2] bc c9 [2] a7 87 [2] 9a }

  condition:
    any of them
}