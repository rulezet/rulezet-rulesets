rule TTP_XOR_MULT_DOSStub_eec9 {
  strings:
    $key_eec9 = { ba a1 [2] ce b9 [2] 89 bb [2] ce aa [2] 80 a6 [2] 8c ac [2] 9b a7 [2] 80 e9 [2] bd }

  condition:
    any of them
}