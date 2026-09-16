rule TTP_XOR_MULT_DOSStub_bda2 {
  strings:
    $key_bda2 = { e9 ca [2] 9d d2 [2] da d0 [2] 9d c1 [2] d3 cd [2] df c7 [2] c8 cc [2] d3 82 [2] ee }

  condition:
    any of them
}