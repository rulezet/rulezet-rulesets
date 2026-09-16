rule TTP_XOR_MULT_DOSStub_bdab {
  strings:
    $key_bdab = { e9 c3 [2] 9d db [2] da d9 [2] 9d c8 [2] d3 c4 [2] df ce [2] c8 c5 [2] d3 8b [2] ee }

  condition:
    any of them
}