rule TTP_XOR_MULT_DOSStub_efb0 {
  strings:
    $key_efb0 = { bb d8 [2] cf c0 [2] 88 c2 [2] cf d3 [2] 81 df [2] 8d d5 [2] 9a de [2] 81 90 [2] bc }

  condition:
    any of them
}