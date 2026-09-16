rule TTP_XOR_MULT_DOSStub_bca4 {
  strings:
    $key_bca4 = { e8 cc [2] 9c d4 [2] db d6 [2] 9c c7 [2] d2 cb [2] de c1 [2] c9 ca [2] d2 84 [2] ef }

  condition:
    any of them
}