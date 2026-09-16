rule TTP_XOR_MULT_DOSStub_efa3 {
  strings:
    $key_efa3 = { bb cb [2] cf d3 [2] 88 d1 [2] cf c0 [2] 81 cc [2] 8d c6 [2] 9a cd [2] 81 83 [2] bc }

  condition:
    any of them
}