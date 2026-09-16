rule TTP_XOR_MULT_DOSStub_fba3 {
  strings:
    $key_fba3 = { af cb [2] db d3 [2] 9c d1 [2] db c0 [2] 95 cc [2] 99 c6 [2] 8e cd [2] 95 83 [2] a8 }

  condition:
    any of them
}