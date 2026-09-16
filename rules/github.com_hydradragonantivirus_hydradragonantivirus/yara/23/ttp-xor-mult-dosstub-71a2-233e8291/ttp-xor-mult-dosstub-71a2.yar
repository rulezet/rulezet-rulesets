rule TTP_XOR_MULT_DOSStub_71a2 {
  strings:
    $key_71a2 = { 25 ca [2] 51 d2 [2] 16 d0 [2] 51 c1 [2] 1f cd [2] 13 c7 [2] 04 cc [2] 1f 82 [2] 22 }

  condition:
    any of them
}