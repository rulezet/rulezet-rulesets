rule TTP_XOR_MULT_DOSStub_41a2 {
  strings:
    $key_41a2 = { 15 ca [2] 61 d2 [2] 26 d0 [2] 61 c1 [2] 2f cd [2] 23 c7 [2] 34 cc [2] 2f 82 [2] 12 }

  condition:
    any of them
}