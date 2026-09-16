rule TTP_XOR_MULT_DOSStub_bdcf {
  strings:
    $key_bdcf = { e9 a7 [2] 9d bf [2] da bd [2] 9d ac [2] d3 a0 [2] df aa [2] c8 a1 [2] d3 ef [2] ee }

  condition:
    any of them
}