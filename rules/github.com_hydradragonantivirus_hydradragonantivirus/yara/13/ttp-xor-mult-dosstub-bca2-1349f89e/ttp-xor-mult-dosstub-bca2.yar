rule TTP_XOR_MULT_DOSStub_bca2 {
  strings:
    $key_bca2 = { e8 ca [2] 9c d2 [2] db d0 [2] 9c c1 [2] d2 cd [2] de c7 [2] c9 cc [2] d2 82 [2] ef }

  condition:
    any of them
}