rule TTP_XOR_MULT_DOSStub_bdbf {
  strings:
    $key_bdbf = { e9 d7 [2] 9d cf [2] da cd [2] 9d dc [2] d3 d0 [2] df da [2] c8 d1 [2] d3 9f [2] ee }

  condition:
    any of them
}