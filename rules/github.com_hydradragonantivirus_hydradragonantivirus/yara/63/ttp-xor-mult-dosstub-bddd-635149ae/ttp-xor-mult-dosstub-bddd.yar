rule TTP_XOR_MULT_DOSStub_bddd {
  strings:
    $key_bddd = { e9 b5 [2] 9d ad [2] da af [2] 9d be [2] d3 b2 [2] df b8 [2] c8 b3 [2] d3 fd [2] ee }

  condition:
    any of them
}