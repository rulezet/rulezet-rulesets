rule TTP_XOR_MULT_DOSStub_feb1 {
  strings:
    $key_feb1 = { aa d9 [2] de c1 [2] 99 c3 [2] de d2 [2] 90 de [2] 9c d4 [2] 8b df [2] 90 91 [2] ad }

  condition:
    any of them
}