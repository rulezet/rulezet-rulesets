rule TTP_XOR_MULT_DOSStub_bdc9 {
  strings:
    $key_bdc9 = { e9 a1 [2] 9d b9 [2] da bb [2] 9d aa [2] d3 a6 [2] df ac [2] c8 a7 [2] d3 e9 [2] ee }

  condition:
    any of them
}