rule TTP_XOR_MULT_DOSStub_feb6 {
  strings:
    $key_feb6 = { aa de [2] de c6 [2] 99 c4 [2] de d5 [2] 90 d9 [2] 9c d3 [2] 8b d8 [2] 90 96 [2] ad }

  condition:
    any of them
}