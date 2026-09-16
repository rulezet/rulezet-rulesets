rule TTP_XOR_MULT_DOSStub_bda3 {
  strings:
    $key_bda3 = { e9 cb [2] 9d d3 [2] da d1 [2] 9d c0 [2] d3 cc [2] df c6 [2] c8 cd [2] d3 83 [2] ee }

  condition:
    any of them
}