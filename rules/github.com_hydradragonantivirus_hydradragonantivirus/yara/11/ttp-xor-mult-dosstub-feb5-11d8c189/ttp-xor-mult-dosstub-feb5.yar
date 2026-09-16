rule TTP_XOR_MULT_DOSStub_feb5 {
  strings:
    $key_feb5 = { aa dd [2] de c5 [2] 99 c7 [2] de d6 [2] 90 da [2] 9c d0 [2] 8b db [2] 90 95 [2] ad }

  condition:
    any of them
}