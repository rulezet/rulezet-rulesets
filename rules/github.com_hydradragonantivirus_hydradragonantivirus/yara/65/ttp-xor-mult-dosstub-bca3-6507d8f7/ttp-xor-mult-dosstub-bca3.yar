rule TTP_XOR_MULT_DOSStub_bca3 {
  strings:
    $key_bca3 = { e8 cb [2] 9c d3 [2] db d1 [2] 9c c0 [2] d2 cc [2] de c6 [2] c9 cd [2] d2 83 [2] ef }

  condition:
    any of them
}