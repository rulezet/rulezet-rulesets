rule TTP_XOR_MULT_DOSStub_35a2 {
  strings:
    $key_35a2 = { 61 ca [2] 15 d2 [2] 52 d0 [2] 15 c1 [2] 5b cd [2] 57 c7 [2] 40 cc [2] 5b 82 [2] 66 }

  condition:
    any of them
}