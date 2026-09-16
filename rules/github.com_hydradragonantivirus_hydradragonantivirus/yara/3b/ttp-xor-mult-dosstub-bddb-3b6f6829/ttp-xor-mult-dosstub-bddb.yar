rule TTP_XOR_MULT_DOSStub_bddb {
  strings:
    $key_bddb = { e9 b3 [2] 9d ab [2] da a9 [2] 9d b8 [2] d3 b4 [2] df be [2] c8 b5 [2] d3 fb [2] ee }

  condition:
    any of them
}