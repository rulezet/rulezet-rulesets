rule TTP_XOR_MULT_DOSStub_efb6 {
  strings:
    $key_efb6 = { bb de [2] cf c6 [2] 88 c4 [2] cf d5 [2] 81 d9 [2] 8d d3 [2] 9a d8 [2] 81 96 [2] bc }

  condition:
    any of them
}