rule TTP_XOR_MULT_DOSStub_bdce {
  strings:
    $key_bdce = { e9 a6 [2] 9d be [2] da bc [2] 9d ad [2] d3 a1 [2] df ab [2] c8 a0 [2] d3 ee [2] ee }

  condition:
    any of them
}