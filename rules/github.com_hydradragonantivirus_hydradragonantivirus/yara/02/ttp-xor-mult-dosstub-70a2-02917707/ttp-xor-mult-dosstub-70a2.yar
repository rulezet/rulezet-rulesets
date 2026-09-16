rule TTP_XOR_MULT_DOSStub_70a2 {
  strings:
    $key_70a2 = { 24 ca [2] 50 d2 [2] 17 d0 [2] 50 c1 [2] 1e cd [2] 12 c7 [2] 05 cc [2] 1e 82 [2] 23 }

  condition:
    any of them
}