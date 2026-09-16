rule TTP_XOR_MULT_DOSStub_bdbd {
  strings:
    $key_bdbd = { e9 d5 [2] 9d cd [2] da cf [2] 9d de [2] d3 d2 [2] df d8 [2] c8 d3 [2] d3 9d [2] ee }

  condition:
    any of them
}