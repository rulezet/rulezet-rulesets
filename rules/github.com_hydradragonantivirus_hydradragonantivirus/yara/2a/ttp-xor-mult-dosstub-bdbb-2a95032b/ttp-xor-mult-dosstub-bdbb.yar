rule TTP_XOR_MULT_DOSStub_bdbb {
  strings:
    $key_bdbb = { e9 d3 [2] 9d cb [2] da c9 [2] 9d d8 [2] d3 d4 [2] df de [2] c8 d5 [2] d3 9b [2] ee }

  condition:
    any of them
}