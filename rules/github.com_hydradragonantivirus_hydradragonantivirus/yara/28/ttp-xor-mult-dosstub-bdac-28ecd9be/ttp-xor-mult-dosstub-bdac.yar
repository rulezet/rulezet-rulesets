rule TTP_XOR_MULT_DOSStub_bdac {
  strings:
    $key_bdac = { e9 c4 [2] 9d dc [2] da de [2] 9d cf [2] d3 c3 [2] df c9 [2] c8 c2 [2] d3 8c [2] ee }

  condition:
    any of them
}